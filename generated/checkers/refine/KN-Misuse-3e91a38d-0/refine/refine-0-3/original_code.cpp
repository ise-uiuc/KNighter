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
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use memdup_array_user for array copy",
                       "API Misuse")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Check if expression (ignoring parens/imp-casts) is a sizeof(...) expr.
  static bool isSizeofExpr(const Expr *E);

  // Return true if 'E' syntactically contains a multiplication with sizeof on
  // one side. Do not traverse into sizeof(...) operands to avoid false hits.
  static const BinaryOperator *findMulWithSizeof(const Expr *E);

  // Filter out benign cases (e.g., plain sizeof(...) without multiplication).
  static bool isFalsePositive(const Expr *SizeArg);

  // Recognize memdup_user (not memdup_user_nul etc.).
  static bool isMemdupUser(const CallEvent &Call);
};

bool SAGenTestChecker::isSizeofExpr(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E))
    return U->getKind() == UETT_SizeOf;
  return false;
}

// Helper: recursively search for a BinaryOperator '*' with one side a sizeof.
// - Ignore parens/implicit casts.
// - Do NOT traverse into sizeof(...) operands to avoid flagging patterns
//   like sizeof(a*b).
static const BinaryOperator *findMulWithSizeofRec(const Expr *E) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  // If we reached a sizeof(...) expression, do not look inside.
  if (isa<UnaryExprOrTypeTraitExpr>(E))
    return nullptr;

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Mul) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (isa<UnaryExprOrTypeTraitExpr>(LHS) ||
          isa<UnaryExprOrTypeTraitExpr>(RHS)) {
        const auto *UL = dyn_cast<UnaryExprOrTypeTraitExpr>(LHS);
        const auto *UR = dyn_cast<UnaryExprOrTypeTraitExpr>(RHS);
        if ((UL && UL->getKind() == UETT_SizeOf) ||
            (UR && UR->getKind() == UETT_SizeOf)) {
          return BO;
        }
      }
    }
    // Recurse into children (still respecting the "don't go inside sizeof" rule)
    if (const BinaryOperator *Found = findMulWithSizeofRec(BO->getLHS()))
      return Found;
    if (const BinaryOperator *Found = findMulWithSizeofRec(BO->getRHS()))
      return Found;
    return nullptr;
  }

  // Ternary operator
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    if (const BinaryOperator *Found = findMulWithSizeofRec(CO->getTrueExpr()))
      return Found;
    if (const BinaryOperator *Found = findMulWithSizeofRec(CO->getFalseExpr()))
      return Found;
    return nullptr;
  }

  // Casts (already ignoring implicit; handle explicit as well)
  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    return findMulWithSizeofRec(CE->getSubExpr());
  }

  // Generic traversal over children for any other Expr subclasses.
  for (const Stmt *Child : E->children()) {
    const auto *ChildE = dyn_cast_or_null<Expr>(Child);
    if (!ChildE)
      continue;
    if (const auto *Found = findMulWithSizeofRec(ChildE))
      return Found;
  }
  return nullptr;
}

const BinaryOperator *SAGenTestChecker::findMulWithSizeof(const Expr *E) {
  return findMulWithSizeofRec(E);
}

bool SAGenTestChecker::isFalsePositive(const Expr *SizeArg) {
  // Suppress when the entire size arg is a plain sizeof(...) of anything.
  // This covers the reported FP: memdup_user(arg, sizeof(*ldpc))
  return isSizeofExpr(SizeArg);
}

bool SAGenTestChecker::isMemdupUser(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == "memdup_user";
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Only interested in direct calls to memdup_user.
  if (!isMemdupUser(Call))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *SizeArg = Call.getArgExpr(1);
  if (!SizeArg)
    return;

  // Suppress plain sizeof(...) calls (dup of a single struct/object).
  if (isFalsePositive(SizeArg))
    return;

  // Find a multiplication with sizeof(...) anywhere in the size argument,
  // but never inside a sizeof operand.
  const BinaryOperator *Mul = findMulWithSizeof(SizeArg);
  if (!Mul)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, "
      "count * elem_size); multiplication may overflow.",
      N);
  // Highlight just the multiplication subexpression for precision.
  R->addRange(Mul->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memdup_user used with count * sizeof(...) and suggests "
      "memdup_array_user",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
