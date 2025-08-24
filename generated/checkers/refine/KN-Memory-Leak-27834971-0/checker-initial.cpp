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
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

//================ Program State Customization ================

// Maps the return symbol of set_memory_decrypted(...) to the pointer's MemRegion passed in arg0.
REGISTER_MAP_WITH_PROGRAMSTATE(SetDecryptRetSymToPtrRegion, SymbolRef, const MemRegion*)
// Tracks when an integer variable holds the return value of set_memory_decrypted(...).
REGISTER_MAP_WITH_PROGRAMSTATE(VarRegionToPtrRegion, const MemRegion*, const MemRegion*)
// Maps the symbolic condition of an if-statement to the pointer’s MemRegion used in set_memory_decrypted(...).
REGISTER_MAP_WITH_PROGRAMSTATE(CondSymToPtrRegion, SymbolRef, const MemRegion*)
// Records condition polarity: whether "condition is true" means failure of set_memory_decrypted(...).
REGISTER_MAP_WITH_PROGRAMSTATE(CondSymTrueMeansFailure, SymbolRef, bool)
// Set of pointer regions that are known to be in failed decryption transition on the current path.
REGISTER_MAP_WITH_PROGRAMSTATE(FailedDecryptRegionSet, const MemRegion*, bool)

namespace {
class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::Bind,
        check::BranchCondition,
        eval::Assume,
        check::PreCall> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
             "Freeing pages after set_memory_decrypted() failure",
             "Memory Management")) {}

  // Callbacks
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond,
                             bool Assumption) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helpers
  bool isAttrTransitionFn(const CallEvent &Call, CheckerContext &C) const;
  bool isPageFreeFn(const CallEvent &Call, CheckerContext &C) const;

  const MemRegion *getPtrRegionFromExprLoose(const Expr *E,
                                             CheckerContext &C) const;

  const Expr *unwrapCondition(const Expr *E, CheckerContext &C) const;

  // Analyze condition for pointer region and polarity:
  // - Returns true on success and sets OutPtr and TrueMeansFailure.
  bool analyzeConditionForPtrAndPolarity(const Expr *CondE,
                                         CheckerContext &C,
                                         const MemRegion *&OutPtr,
                                         bool &TrueMeansFailure) const;

  // Small helpers
  bool isZeroInteger(const Expr *E, CheckerContext &C) const;
  bool callExprIsAttrTransition(const Expr *E, CheckerContext &C) const;
};

//================ Helper Implementations ================

bool SAGenTestChecker::isAttrTransitionFn(const CallEvent &Call,
                                          CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  // Use ExprHasName for robust callee matching
  if (ExprHasName(OriginExpr, "set_memory_decrypted", C))
    return true;
  return false;
}

bool SAGenTestChecker::isPageFreeFn(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  // Focus on free_pages_exact for this checker (extendable)
  if (ExprHasName(OriginExpr, "free_pages_exact", C))
    return true;
  return false;
}

const MemRegion *SAGenTestChecker::getPtrRegionFromExprLoose(const Expr *E,
                                                             CheckerContext &C) const {
  if (!E)
    return nullptr;

  // First, try directly
  if (const MemRegion *MR = getMemRegionFromExpr(E, C)) {
    return MR->getBaseRegion();
  }

  // If that fails (due to casts like (unsigned long)addr), try to find a DeclRefExpr child.
  if (const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    if (const MemRegion *MR = getMemRegionFromExpr(DRE, C)) {
      return MR->getBaseRegion();
    }
  }

  return nullptr;
}

const Expr *SAGenTestChecker::unwrapCondition(const Expr *E,
                                              CheckerContext &C) const {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();

  // Unwrap likely/unlikely/__builtin_expect(foo, ...)
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    const Expr *CalleeE = CE->getCallee();
    if (CalleeE &&
        (ExprHasName(CalleeE, "__builtin_expect", C) ||
         ExprHasName(E, "likely", C) ||
         ExprHasName(E, "unlikely", C))) {
      if (CE->getNumArgs() > 0) {
        return unwrapCondition(CE->getArg(0), C);
      }
    }
  }

  return E;
}

bool SAGenTestChecker::isZeroInteger(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C)) {
    return Res == 0;
  }
  return false;
}

bool SAGenTestChecker::callExprIsAttrTransition(const Expr *E,
                                                CheckerContext &C) const {
  if (!E)
    return false;
  const CallExpr *CE = dyn_cast<CallExpr>(E);
  if (!CE)
    return false;
  // Use source text matching via ExprHasName
  return ExprHasName(CE, "set_memory_decrypted", C);
}

bool SAGenTestChecker::analyzeConditionForPtrAndPolarity(const Expr *CondE,
                                                         CheckerContext &C,
                                                         const MemRegion *&OutPtr,
                                                         bool &TrueMeansFailure) const {
  OutPtr = nullptr;
  TrueMeansFailure = true; // default conservative

  if (!CondE)
    return false;

  const Expr *E = unwrapCondition(CondE, C);
  if (!E)
    return false;

  // 1) Handle negation: !X
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = unwrapCondition(UO->getSubExpr(), C);
      if (!Sub)
        return false;

      // !set_memory_decrypted(...)
      if (callExprIsAttrTransition(Sub, C)) {
        const auto *CE = dyn_cast<CallExpr>(Sub);
        if (!CE || CE->getNumArgs() < 1)
          return false;
        OutPtr = getPtrRegionFromExprLoose(CE->getArg(0), C);
        if (!OutPtr)
          return false;
        TrueMeansFailure = false; // !call: true => success; false => failure
        return true;
      }

      // !ret  (variable holding return of set_memory_decrypted)
      if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(Sub)) {
        const MemRegion *VarR = getMemRegionFromExpr(DRE, C);
        if (!VarR)
          return false;
        VarR = VarR->getBaseRegion();
        if (!VarR)
          return false;
        ProgramStateRef State = C.getState();
        if (const MemRegion *PtrR = State->get<VarRegionToPtrRegion>(VarR)) {
          OutPtr = PtrR;
          TrueMeansFailure = false;
          return true;
        }
      }
      return false;
    }
  }

  // 2) Handle equality/inequality with zero: X == 0, X != 0
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = unwrapCondition(BO->getLHS(), C);
      const Expr *RHS = unwrapCondition(BO->getRHS(), C);

      // Identify zero side and expression side
      const Expr *ExprSide = nullptr;
      if (isZeroInteger(LHS, C) && RHS)
        ExprSide = RHS;
      else if (isZeroInteger(RHS, C) && LHS)
        ExprSide = LHS;

      if (ExprSide) {
        // set_memory_decrypted(...) ==/!= 0
        if (callExprIsAttrTransition(ExprSide, C)) {
          const auto *CE = dyn_cast<CallExpr>(ExprSide);
          if (!CE || CE->getNumArgs() < 1)
            return false;
          OutPtr = getPtrRegionFromExprLoose(CE->getArg(0), C);
          if (!OutPtr)
            return false;
          TrueMeansFailure = (Op == BO_NE); // call != 0 => failure when true
          return true;
        }

        // ret ==/!= 0
        if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(ExprSide)) {
          const MemRegion *VarR = getMemRegionFromExpr(DRE, C);
          if (!VarR)
            return false;
          VarR = VarR->getBaseRegion();
          if (!VarR)
            return false;
          ProgramStateRef State = C.getState();
          if (const MemRegion *PtrR = State->get<VarRegionToPtrRegion>(VarR)) {
            OutPtr = PtrR;
            TrueMeansFailure = (Op == BO_NE);
            return true;
          }
        }
      }
    }
  }

  // 3) Direct call: if (set_memory_decrypted(...))
  if (callExprIsAttrTransition(E, C)) {
    const auto *CE = dyn_cast<CallExpr>(E);
    if (!CE || CE->getNumArgs() < 1)
      return false;
    OutPtr = getPtrRegionFromExprLoose(CE->getArg(0), C);
    if (!OutPtr)
      return false;
    TrueMeansFailure = true; // if (call) => failure when true
    return true;
  }

  // 4) Variable alone: if (ret)
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    const MemRegion *VarR = getMemRegionFromExpr(DRE, C);
    if (VarR) {
      VarR = VarR->getBaseRegion();
      if (VarR) {
        ProgramStateRef State = C.getState();
        if (const MemRegion *PtrR = State->get<VarRegionToPtrRegion>(VarR)) {
          OutPtr = PtrR;
          TrueMeansFailure = true; // if (ret) => failure when true
          return true;
        }
      }
    }
  }

  return false;
}

//================ Core Callbacks ================

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isAttrTransitionFn(Call, C))
    return;

  // Extract the pointer region from arg0 (may be wrapped in casts).
  const Expr *Arg0E = Call.getArgExpr(0);
  const MemRegion *PtrR = getPtrRegionFromExprLoose(Arg0E, C);
  if (!PtrR)
    return;

  // Get the return symbol of set_memory_decrypted(...)
  SVal RetVal = Call.getReturnValue();
  SymbolRef RetSym = RetVal.getAsSymbol();
  if (!RetSym)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<SetDecryptRetSymToPtrRegion>(RetSym, PtrR);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  // If we bind ret = (symbol from set_memory_decrypted(...)), track that
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  SymbolRef Sym = Val.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  if (const MemRegion *PtrR = State->get<SetDecryptRetSymToPtrRegion>(Sym)) {
    State = State->set<VarRegionToPtrRegion>(LHSReg, PtrR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  const MemRegion *PtrR = nullptr;
  bool TrueMeansFailure = true;

  if (!analyzeConditionForPtrAndPolarity(CondE, C, PtrR, TrueMeansFailure)) {
    C.addTransition(State);
    return;
  }

  // Map the symbolic condition to pointer region and polarity
  SVal CondVal = State->getSVal(CondE, C.getLocationContext());
  SymbolRef CondSym = CondVal.getAsSymbol();
  if (!CondSym) {
    C.addTransition(State);
    return;
  }

  State = State->set<CondSymToPtrRegion>(CondSym, PtrR);
  State = State->set<CondSymTrueMeansFailure>(CondSym, TrueMeansFailure);
  C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond,
                                             bool Assumption) const {
  SymbolRef CondSym = Cond.getAsSymbol();
  if (!CondSym)
    return State;

  const MemRegion *PtrR = State->get<CondSymToPtrRegion>(CondSym);
  if (!PtrR)
    return State;

  const bool *TMFPtr = State->get<CondSymTrueMeansFailure>(CondSym);
  bool TrueMeansFailure = TMFPtr ? *TMFPtr : true;

  // If assumption matches polarity, then we are on "failure" path.
  if (Assumption == TrueMeansFailure) {
    State = State->set<FailedDecryptRegionSet>(PtrR, true);
  } else {
    State = State->remove<FailedDecryptRegionSet>(PtrR);
  }

  return State;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isPageFreeFn(Call, C))
    return;

  const Expr *Arg0E = Call.getArgExpr(0);
  const MemRegion *FreeR = getPtrRegionFromExprLoose(Arg0E, C);
  if (!FreeR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Failed = State->get<FailedDecryptRegionSet>(FreeR);
  if (Failed && *Failed) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Freeing pages after set_memory_decrypted() failure", N);
    R->addRange(Call.getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing of pages after set_memory_decrypted() failure", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
