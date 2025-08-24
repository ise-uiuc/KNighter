#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/OperationKinds.h"
#include "clang/Lex/Lexer.h"
#include <string>
#include <vector>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are necessary.

namespace {

struct AllocFnInfo {
  const char *Name;
  unsigned SizeIndex;
  const char *Recommendation;
};

static const AllocFnInfo AllocFns[] = {
    {"kmalloc", 0, "kcalloc() or kmalloc_array()"},
    {"kzalloc", 0, "kcalloc()"},
    {"__kmalloc", 0, "kcalloc() or kmalloc_array()"},
    {"kvmalloc", 0, "kcalloc() or kmalloc_array()"},
    {"kvzalloc", 0, "kcalloc()"},
    {"devm_kmalloc", 1, "devm_kcalloc() or kmalloc_array()"},
    {"devm_kzalloc", 1, "devm_kcalloc()"},
};

// Helper: strip parentheses and implicit casts
static const Expr *strip(const Expr *E) {
  return E ? E->IgnoreParenImpCasts() : nullptr;
}

// Helper: recursively flatten a multiplication expression into factors.
static void flattenMulFactors(const Expr *E, llvm::SmallVector<const Expr *, 8> &Out) {
  E = strip(E);
  if (!E) {
    return;
  }
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Mul) {
      flattenMulFactors(BO->getLHS(), Out);
      flattenMulFactors(BO->getRHS(), Out);
      return;
    }
  }
  Out.push_back(E);
}

// Helper: check if any factor is a sizeof(...) expression.
static bool hasSizeofFactor(llvm::ArrayRef<const Expr *> Factors) {
  for (const Expr *F : Factors) {
    if (const auto *UETT = dyn_cast<UnaryExprOrTypeTraitExpr>(strip(F))) {
      if (UETT->getKind() == UETT_SizeOf)
        return true;
    }
  }
  return false;
}

// Helper: suppress known safe macros that already perform checked sizing.
static bool containsSafeMacro(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  // Conservatively suppress some well-known safe helpers/macros.
  if (ExprHasName(E, "struct_size", C))
    return true;
  if (ExprHasName(E, "array_size", C))
    return true;
  if (ExprHasName(E, "size_mul", C))
    return true;

  return false;
}

// Determine if the expression is a manual array size computation like sizeof(T) * n.
static bool isManualArraySizeExpr(const Expr *E, CheckerContext &C) {
  E = strip(E);
  if (!E)
    return false;

  if (containsSafeMacro(E, C))
    return false;

  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return false;

  llvm::SmallVector<const Expr *, 8> Factors;
  flattenMulFactors(E, Factors);
  if (Factors.size() < 2)
    return false;

  if (!hasSizeofFactor(Factors))
    return false;

  return true;
}

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Array allocation via kmalloc/kzalloc may overflow", "Memory")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // No additional stateful helpers needed.
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Identify if this call is one of the tracked allocation APIs using ExprHasName.
  const AllocFnInfo *Matched = nullptr;
  for (const auto &Info : AllocFns) {
    if (ExprHasName(Origin, Info.Name, C)) {
      Matched = &Info;
      break;
    }
  }
  if (!Matched)
    return;

  if (Call.getNumArgs() <= Matched->SizeIndex)
    return;

  const Expr *SizeArg = Call.getArgExpr(Matched->SizeIndex);
  if (!SizeArg)
    return;

  if (!isManualArraySizeExpr(SizeArg, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg = std::string("Use ") + Matched->Recommendation +
                    " for array allocations; manual size multiplication can overflow";
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(SizeArg->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect manual sizeof(...) * count in kmalloc/kzalloc and suggest kcalloc/kmalloc_array to avoid overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
