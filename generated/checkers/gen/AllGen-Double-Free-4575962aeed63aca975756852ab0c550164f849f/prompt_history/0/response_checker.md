```cpp
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
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(DevmAllocSyms, SymbolRef)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker()
          : BT(new BugType(this, "Double free of devm-managed pointer", "Memory Management")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      static bool isDevmAllocator(const CallEvent &Call, CheckerContext &C);
      static bool functionKnownToFree(const CallEvent &Call,
                                      llvm::SmallVectorImpl<unsigned> &FreedParams,
                                      CheckerContext &C);
      static SymbolRef getPtrSymbolFromSVal(SVal V);
      void reportManualFreeOfDevm(const CallEvent &Call, const Expr *ArgE, CheckerContext &C) const;
};

static bool isNameOneOf(const Expr *E, CheckerContext &C,
                        std::initializer_list<const char*> Names) {
  if (!E) return false;
  for (const char *N : Names) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isDevmAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  return isNameOneOf(OE, C, {
    "devm_kcalloc",
    "devm_kmalloc",
    "devm_kmalloc_array",
    "devm_kzalloc",
    "devm_kcalloc_node",
    "devm_kmalloc_node",
    "devm_kasprintf"
  });
}

bool SAGenTestChecker::functionKnownToFree(const CallEvent &Call,
                                           llvm::SmallVectorImpl<unsigned> &FreedParams,
                                           CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  if (ExprHasName(OE, "kfree", C) ||
      ExprHasName(OE, "kvfree", C) ||
      ExprHasName(OE, "vfree", C)) {
    FreedParams.push_back(0);
    return true;
  }

  if (ExprHasName(OE, "pinctrl_utils_free_map", C)) {
    // pinctrl_utils_free_map(pctldev, map, nmaps)
    FreedParams.push_back(1);
    return true;
  }

  return false;
}

SymbolRef SAGenTestChecker::getPtrSymbolFromSVal(SVal V) {
  if (SymbolRef S = V.getAsSymbol())
    return S;

  if (const MemRegion *MR = V.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
      return SR->getSymbol();
  }
  return nullptr;
}

void SAGenTestChecker::reportManualFreeOfDevm(const CallEvent &Call, const Expr *ArgE,
                                              CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Manual free of devm_* allocated pointer (double free)", N);
  if (ArgE)
    R->addRange(ArgE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isDevmAllocator(Call, C))
    return;

  ProgramStateRef State = C.getState();

  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = getPtrSymbolFromSVal(Ret);
  if (!Sym)
    return;

  if (!State->contains<DevmAllocSyms>(Sym)) {
    State = State->add<DevmAllocSyms>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> FreedParams;
  if (!functionKnownToFree(Call, FreedParams, C))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : FreedParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    SVal ArgV = Call.getArgSVal(Idx);

    // Skip definite NULL frees if trivially known; conservatively continue otherwise.
    if (ArgV.isZeroConstant())
      continue;

    SymbolRef Sym = getPtrSymbolFromSVal(ArgV);
    if (!Sym)
      continue;

    if (State->contains<DevmAllocSyms>(Sym)) {
      reportManualFreeOfDevm(Call, ArgE, C);
      // One report per call site is enough.
      return;
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect manual free of devm_* allocated pointers (double free)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
