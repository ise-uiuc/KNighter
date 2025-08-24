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
#include "clang/AST/Stmt.h"
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states

// Return symbol of allocator -> resource kind
REGISTER_MAP_WITH_PROGRAMSTATE(RetSymResKindMap, SymbolRef, unsigned)
// Return symbol of allocator -> enclosing loop (ForStmt*)
REGISTER_MAP_WITH_PROGRAMSTATE(RetSymLoopMap, SymbolRef, const Stmt *)
// Variable region that holds resource -> resource kind
REGISTER_MAP_WITH_PROGRAMSTATE(ResKindMap, const MemRegion *, unsigned)
// Variable region -> enclosing loop (ForStmt*)
REGISTER_MAP_WITH_PROGRAMSTATE(ResLoopMap, const MemRegion *, const Stmt *)
// LabelDecl -> is this a label to a pre-decrement cleanup loop?
REGISTER_MAP_WITH_PROGRAMSTATE(LabelCleanupMap, const LabelDecl *, bool)

namespace {

enum ResourceKind : unsigned {
  KindNetdev = 1
};

class SAGenTestChecker
    : public Checker<check::BeginFunction,
                     check::PostCall,
                     check::Bind,
                     check::PreCall,
                     check::PreStmt<GotoStmt>,
                     check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Resource leak on error path in creation loop",
                       "Memory Leak")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const GotoStmt *GS, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helpers
  static bool isAllocNetdev(const CallEvent &Call, CheckerContext &C);
  static bool isFreeNetdev(const CallEvent &Call, CheckerContext &C);

  static bool isZeroIntegerLiteral(const Expr *E, CheckerContext &C);
  static bool whileHasPreDecCleanupPattern(const WhileStmt *WS,
                                           CheckerContext &C);
  static bool containsPreDecCleanup(const Stmt *S, CheckerContext &C);

  static const MemRegion *getVarRegionFromExpr(const Expr *E,
                                               CheckerContext &C);

  static ProgramStateRef clearResourceForRegion(ProgramStateRef State,
                                                const MemRegion *MR);
};

// ---------- Helper implementations ----------

bool SAGenTestChecker::isAllocNetdev(const CallEvent &Call,
                                     CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "alloc_etherdev", C) ||
         ExprHasName(E, "alloc_etherdev_mqs", C);
}

bool SAGenTestChecker::isFreeNetdev(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "free_netdev", C);
}

bool SAGenTestChecker::isZeroIntegerLiteral(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt Res;
  if (!EvaluateExprToInt(Res, E->IgnoreImpCasts(), C))
    return false;
  return Res.isZero();
}

bool SAGenTestChecker::whileHasPreDecCleanupPattern(const WhileStmt *WS,
                                                    CheckerContext &C) {
  if (!WS)
    return false;
  const Expr *Cond = WS->getCond();
  if (!Cond)
    return false;

  Cond = Cond->IgnoreParenCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return false;

  if (BO->getOpcode() != BO_GE)
    return false;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return false;

  LHS = LHS->IgnoreParenCasts();
  const auto *UO = dyn_cast<UnaryOperator>(LHS);
  if (!UO || UO->getOpcode() != UO_PreDec)
    return false;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
  if (!isa<DeclRefExpr>(Sub))
    return false;

  // RHS should be 0
  if (!isZeroIntegerLiteral(RHS, C))
    return false;

  return true;
}

bool SAGenTestChecker::containsPreDecCleanup(const Stmt *S,
                                             CheckerContext &C) {
  if (!S)
    return false;

  if (const auto *WS = dyn_cast<WhileStmt>(S)) {
    if (whileHasPreDecCleanupPattern(WS, C))
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (Child && containsPreDecCleanup(Child, C))
      return true;
  }
  return false;
}

const MemRegion *SAGenTestChecker::getVarRegionFromExpr(const Expr *E,
                                                        CheckerContext &C) {
  if (!E)
    return nullptr;
  const Expr *EE = E->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(EE);
  if (!DRE)
    return nullptr;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  const MemRegion *VR =
      MRMgr.getVarRegion(VD, C.getLocationContext())->getBaseRegion();
  return VR;
}

ProgramStateRef SAGenTestChecker::clearResourceForRegion(ProgramStateRef State,
                                                         const MemRegion *MR) {
  if (!MR)
    return State;
  State = State->remove<ResKindMap>(MR);
  State = State->remove<ResLoopMap>(MR);
  return State;
}

// ---------- Checker callbacks ----------

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const LocationContext *LCtx = C.getLocationContext();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  const Stmt *Body = FD->getBody();
  if (!Body) {
    C.addTransition(State);
    return;
  }

  // Walk and record labels that lead to a cleanup loop with "--idx >= 0".
  llvm::SmallVector<const LabelStmt *, 8> Labels;
  // Simple DFS to collect labels and mark those with target pattern
  std::function<void(const Stmt *)> Collect = [&](const Stmt *S) {
    if (!S)
      return;
    if (const auto *LS = dyn_cast<LabelStmt>(S)) {
      if (containsPreDecCleanup(LS->getSubStmt(), C)) {
        const LabelDecl *LD = LS->getDecl();
        State = State->set<LabelCleanupMap>(LD, true);
      }
      // Also visit substmt to find nested labels
      Collect(LS->getSubStmt());
      return;
    }
    for (const Stmt *Child : S->children())
      Collect(Child);
  };

  Collect(Body);

  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isAllocNetdev(Call, C))
    return;

  ProgramStateRef State = C.getState();

  SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
  if (!RetSym)
    return;

  const ForStmt *Loop = findSpecificTypeInParents<ForStmt>(Call.getOriginExpr(), C);

  State = State->set<RetSymResKindMap>(RetSym, KindNetdev);
  State = State->set<RetSymLoopMap>(RetSym, Loop);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If the bound value is the return symbol of an allocator, move it to
  // variable-region based tracking tied to the loop where it was created.
  if (SymbolRef Sym = Val.getAsSymbol()) {
    const unsigned *KindPtr = State->get<RetSymResKindMap>(Sym);
    if (KindPtr) {
      unsigned Kind = *KindPtr;
      const Stmt *Loop = State->get<RetSymLoopMap>(Sym);

      const MemRegion *MR = Loc.getAsRegion();
      if (MR)
        MR = MR->getBaseRegion();

      if (MR) {
        State = State->set<ResKindMap>(MR, Kind);
        State = State->set<ResLoopMap>(MR, Loop);
      }

      State = State->remove<RetSymResKindMap>(Sym);
      State = State->remove<RetSymLoopMap>(Sym);

      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isFreeNetdev(Call, C))
    return;

  ProgramStateRef State = C.getState();

  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg0 = Call.getArgExpr(0);
  const MemRegion *VR = getVarRegionFromExpr(Arg0, C);
  if (!VR)
    return;

  VR = VR->getBaseRegion();
  const unsigned *KindPtr = State->get<ResKindMap>(VR);
  if (!KindPtr)
    return;

  // We recognize it as tracked resource, clear it.
  State = clearResourceForRegion(State, VR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const GotoStmt *GS,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!GS)
    return;

  const LabelDecl *LD = GS->getLabel();
  if (!LD)
    return;

  const bool *IsCleanup = State->get<LabelCleanupMap>(LD);
  if (!IsCleanup || !*IsCleanup)
    return;

  const ForStmt *CurLoop = findSpecificTypeInParents<ForStmt>(GS, C);
  if (!CurLoop)
    return;

  // Iterate tracked resources and see if any was created in this loop and not
  // freed yet, and the current pointer is definitely not null.
  auto Map = State->get<ResKindMap>();
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    const MemRegion *MR = I->first;
    if (!MR)
      continue;

    const Stmt *ResLoop = State->get<ResLoopMap>(MR);
    if (!ResLoop || ResLoop != CurLoop)
      continue;

    // Check that the pointer variable is not definitely null on this path.
    SVal PtrVal = State->getSVal(loc::MemRegionVal(MR));
    if (auto DV = PtrVal.getAs<DefinedSVal>()) {
      ProgramStateRef StNotNull = State->assume(*DV, true);
      if (!StNotNull)
        continue; // Definitely null, not an allocated resource
    } else {
      // If we cannot determine, be conservative and do not warn.
      continue;
    }

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    std::string Msg = "Leak: current iteration resource not freed before goto cleanup";
    if (const auto *VR = dyn_cast<VarRegion>(MR)) {
      if (const auto *VD = dyn_cast<VarDecl>(VR->getDecl())) {
        StringRef Name = VD->getName();
        if (!Name.empty()) {
          Msg += " (e.g., '";
          Msg += Name.str();
          Msg += "')";
        }
      }
    }

    auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
    R->addRange(GS->getSourceRange());
    C.emitReport(std::move(R));
    break; // Report once per goto
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  // No explicit cleanup required; program state traits are path-local.
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects leak when goto jumps to pre-decrement cleanup skipping current item",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
