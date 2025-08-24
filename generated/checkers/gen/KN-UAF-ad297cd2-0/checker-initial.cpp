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

// Program state customization
REGISTER_MAP_WITH_PROGRAMSTATE(PrivToNetdev, SymbolRef, SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(FreedNetdevSet, SymbolRef)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Use-after-free (netdev_priv after free_netdev)",
                       "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  bool isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) const;
  bool getBasePointerSymbolFromExpr(const Expr *E, CheckerContext &C, SymbolRef &OutSym) const;
  bool getBasePointerSymbolFromStmt(const Stmt *S, CheckerContext &C, SymbolRef &OutSym) const;
  void reportUAF(CheckerContext &C, const Stmt *S) const;

  bool isNetdevFreedForPriv(SymbolRef PrivSym, ProgramStateRef State) const;
};

bool SAGenTestChecker::isCallNamed(const CallEvent &Call, StringRef Name,
                                   CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  return ExprHasName(OE, Name, C);
}

bool SAGenTestChecker::getBasePointerSymbolFromExpr(const Expr *E,
                                                    CheckerContext &C,
                                                    SymbolRef &OutSym) const {
  if (!E)
    return false;

  // Search for patterns that imply dereference of a pointer:
  // 1) MemberExpr with '->'
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(E)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase();
      if (!Base)
        return false;
      ProgramStateRef State = C.getState();
      SVal V = State->getSVal(Base, C.getLocationContext());
      if (SymbolRef S = V.getAsSymbol()) {
        OutSym = S;
        return true;
      }
    }
  }

  // 2) UnaryOperator '*' (dereference)
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr();
      if (!Sub)
        return false;
      ProgramStateRef State = C.getState();
      SVal V = State->getSVal(Sub, C.getLocationContext());
      if (SymbolRef S = V.getAsSymbol()) {
        OutSym = S;
        return true;
      }
    }
  }

  // 3) ArraySubscript 'ptr[i]'
  if (const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(E)) {
    const Expr *Base = ASE->getBase();
    if (!Base)
      return false;
    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(Base, C.getLocationContext());
    if (SymbolRef S = V.getAsSymbol()) {
      OutSym = S;
      return true;
    }
  }

  return false;
}

bool SAGenTestChecker::getBasePointerSymbolFromStmt(const Stmt *S,
                                                    CheckerContext &C,
                                                    SymbolRef &OutSym) const {
  if (!S)
    return false;

  if (const auto *E = dyn_cast<Expr>(S)) {
    return getBasePointerSymbolFromExpr(E, C, OutSym);
  }

  // If not an expression, try to find an expression child and analyze it.
  if (const auto *ChildME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ChildME->isArrow()) {
      const Expr *Base = ChildME->getBase();
      if (Base) {
        return getBasePointerSymbolFromExpr(Base, C, OutSym);
      }
    }
  }
  if (const auto *ChildUO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (ChildUO->getOpcode() == UO_Deref) {
      const Expr *Sub = ChildUO->getSubExpr();
      if (Sub) {
        ProgramStateRef State = C.getState();
        SVal V = State->getSVal(Sub, C.getLocationContext());
        if (SymbolRef S = V.getAsSymbol()) {
          OutSym = S;
          return true;
        }
      }
    }
  }
  if (const auto *ChildASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S)) {
    const Expr *Base = ChildASE->getBase();
    if (Base)
      return getBasePointerSymbolFromExpr(Base, C, OutSym);
  }

  return false;
}

bool SAGenTestChecker::isNetdevFreedForPriv(SymbolRef PrivSym,
                                            ProgramStateRef State) const {
  if (!PrivSym || !State)
    return false;

  const SymbolRef *NetSym = State->get<PrivToNetdev>(PrivSym);
  if (!NetSym || !*NetSym)
    return false;

  return State->contains<FreedNetdevSet>(*NetSym);
}

void SAGenTestChecker::reportUAF(CheckerContext &C, const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use of netdev_priv() data after free_netdev()", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!State)
    return;

  // Track netdev_priv(): map return symbol (private) -> net_device symbol (arg0)
  if (isCallNamed(Call, "netdev_priv", C)) {
    SymbolRef PrivSym = Call.getReturnValue().getAsSymbol();
    if (!PrivSym)
      return;

    SVal Arg0Val = Call.getArgSVal(0);
    SymbolRef NetSym = Arg0Val.getAsSymbol();
    if (!NetSym)
      return;

    State = State->set<PrivToNetdev>(PrivSym, NetSym);
    C.addTransition(State);
    return;
  }

  // Track free_netdev(): mark the net_device symbol as freed
  if (isCallNamed(Call, "free_netdev", C)) {
    SVal Arg0Val = Call.getArgSVal(0);
    SymbolRef NetSym = Arg0Val.getAsSymbol();
    if (!NetSym)
      return;

    State = State->add<FreedNetdevSet>(NetSym);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!State)
    return;

  // First, for each argument, detect if its evaluation implicitly dereferences a private pointer
  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    if (!ArgE)
      continue;

    SymbolRef BasePtrSym = nullptr;
    if (getBasePointerSymbolFromExpr(ArgE, C, BasePtrSym)) {
      if (isNetdevFreedForPriv(BasePtrSym, State)) {
        reportUAF(C, Call.getOriginExpr());
        return;
      }
    }
  }

  // Next, if the callee is known to dereference certain pointer params, check them
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (functionKnownToDeref(Call, DerefParams)) {
    for (unsigned Idx : DerefParams) {
      if (Idx >= Call.getNumArgs())
        continue;
      SVal ArgV = Call.getArgSVal(Idx);
      SymbolRef ArgSym = ArgV.getAsSymbol();
      if (!ArgSym)
        continue;

      if (isNetdevFreedForPriv(ArgSym, State)) {
        reportUAF(C, Call.getOriginExpr());
        return;
      }
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!State || !S)
    return;

  // Attempt to extract the base pointer being dereferenced from the statement
  SymbolRef BasePtrSym = nullptr;
  if (!getBasePointerSymbolFromStmt(S, C, BasePtrSym))
    return;

  if (isNetdevFreedForPriv(BasePtrSym, State)) {
    reportUAF(C, S);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free: using netdev_priv() data after free_netdev()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
