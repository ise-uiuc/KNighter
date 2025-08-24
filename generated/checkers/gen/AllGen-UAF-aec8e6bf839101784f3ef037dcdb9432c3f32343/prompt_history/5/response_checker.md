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
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state to track which struct variable needs members to be NULLed after close.
REGISTER_MAP_WITH_PROGRAMSTATE(CloseNeedsNullMap, const VarDecl*, unsigned)
// Program state to remember where the close was observed (for diagnostics).
REGISTER_MAP_WITH_PROGRAMSTATE(CloseOriginMap, const VarDecl*, const Stmt*)

namespace {

static constexpr unsigned BIT_BDEV = 0x1;
static constexpr unsigned BIT_BDEV_FILE = 0x2;

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::Bind,
        check::PreCall,
        check::BranchCondition,
        check::EndFunction> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Stale member pointer after close", "Memory Safety")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:
      // Helpers
      static bool hasCalleeName(const CallEvent &Call, StringRef Name, CheckerContext &C);
      static bool isBtrfsCloseBdev(const CallEvent &Call, CheckerContext &C);
      static const VarDecl* getBaseVarDeclOfExpr(const Expr *E);
      static bool isNullAssigned(SVal V, const Expr *MaybeRHS, CheckerContext &C);
      static const MemberExpr* getMemberExprFrom(const Expr *E);
      static StringRef getFieldNameFromFD(const FieldDecl *FD);
      void reportImmediateUseAfterClose(const Stmt *UseSite, const VarDecl *VD, StringRef FieldName,
                                        const Stmt *CloseSite, CheckerContext &C) const;
      void reportMissingNullAtEnd(const VarDecl *VD, unsigned Mask, const Stmt *CloseSite,
                                  CheckerContext &C) const;
};

// Helper: check callee name using ExprHasName (robust against aliases/macros).
bool SAGenTestChecker::hasCalleeName(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, Name, C);
}

bool SAGenTestChecker::isBtrfsCloseBdev(const CallEvent &Call, CheckerContext &C) {
  // Strict match per patch. Can be extended if needed.
  return hasCalleeName(Call, "btrfs_close_bdev", C);
}

// Extract the base VarDecl* from an expression like "device", "device->field", "(*device).field", etc.
const VarDecl* SAGenTestChecker::getBaseVarDeclOfExpr(const Expr *E) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD;
    return nullptr;
  }

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    return getBaseVarDeclOfExpr(ME->getBase());
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    // Handle deref like *p
    if (UO->getOpcode() == UO_Deref)
      return getBaseVarDeclOfExpr(UO->getSubExpr());
  }

  // Fallback: try to find a DeclRefExpr in children
  if (const auto *InnerDRE = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(InnerDRE->getDecl()))
      return VD;
  }

  return nullptr;
}

// Determine if an assignment value represents NULL/0.
bool SAGenTestChecker::isNullAssigned(SVal V, const Expr *MaybeRHS, CheckerContext &C) {
  if (V.isZeroConstant())
    return true;

  if (MaybeRHS) {
    llvm::APSInt Res;
    if (EvaluateExprToInt(Res, MaybeRHS, C)) {
      if (Res == 0)
        return true;
    }
  }

  return false;
}

const MemberExpr* SAGenTestChecker::getMemberExprFrom(const Expr *E) {
  if (!E) return nullptr;
  const Expr *I = E->IgnoreParenCasts();
  if (const auto *ME = dyn_cast<MemberExpr>(I))
    return ME;
  return findSpecificTypeInChildren<MemberExpr>(I);
}

StringRef SAGenTestChecker::getFieldNameFromFD(const FieldDecl *FD) {
  if (!FD) return StringRef();
  return FD->getName();
}

void SAGenTestChecker::reportImmediateUseAfterClose(const Stmt *UseSite, const VarDecl *VD, StringRef FieldName,
                                                    const Stmt *CloseSite, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg = ("Use-after-free of '" + VD->getName().str() + "->" + FieldName.str() + "' after close").str();
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (UseSite)
    R->addRange(UseSite->getSourceRange());
  if (CloseSite)
    R->addNote("Closed here", CloseSite->getBeginLoc());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportMissingNullAtEnd(const VarDecl *VD, unsigned Mask, const Stmt *CloseSite,
                                              CheckerContext &C) const {
  if (!VD) return;

  // We only report for bdev_file as per target patch; but also permit bdev if needed.
  if (Mask & BIT_BDEV_FILE) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Member 'bdev_file' not set to NULL after close; may cause use-after-free", N);

    if (CloseSite)
      R->addNote("Closed here", CloseSite->getBeginLoc());
    C.emitReport(std::move(R));
  }
}

// Post-call: after calling btrfs_close_bdev(device), require both device->bdev and device->bdev_file to be set to NULL.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isBtrfsCloseBdev(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg0 = Call.getArgExpr(0);
  const VarDecl *VD = getBaseVarDeclOfExpr(Arg0);
  if (!VD)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<CloseNeedsNullMap>(VD, BIT_BDEV | BIT_BDEV_FILE);
  const Stmt *Origin = Call.getOriginExpr();
  if (Origin)
    State = State->set<CloseOriginMap>(VD, Origin);

  C.addTransition(State);
}

// Bind: track assignments to device->bdev and device->bdev_file and clear bits if assigned NULL.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const FieldRegion *FR = dyn_cast_or_null<FieldRegion>(Loc.getAsRegion());
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD)
    return;

  StringRef FieldName = getFieldNameFromFD(FD);
  if (!(FieldName == "bdev" || FieldName == "bdev_file"))
    return;

  const BinaryOperator *BO = dyn_cast_or_null<BinaryOperator>(S);
  const Expr *RHS = BO ? BO->getRHS() : nullptr;

  if (!isNullAssigned(Val, RHS, C))
    return;

  // Find the MemberExpr on the LHS to get the base VarDecl
  const MemberExpr *ME = nullptr;
  if (BO) {
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      ME = findSpecificTypeInChildren<MemberExpr>(LHS);
  }
  if (!ME)
    ME = findSpecificTypeInChildren<MemberExpr>(S);

  const VarDecl *BaseVD = nullptr;
  if (ME)
    BaseVD = getBaseVarDeclOfExpr(ME->getBase());

  if (!BaseVD)
    return;

  ProgramStateRef State = C.getState();
  const unsigned *MaskPtr = State->get<CloseNeedsNullMap>(BaseVD);
  if (!MaskPtr)
    return;

  unsigned Mask = *MaskPtr;
  bool Changed = false;

  if (FieldName == "bdev" && (Mask & BIT_BDEV)) {
    Mask &= ~BIT_BDEV;
    Changed = true;
  } else if (FieldName == "bdev_file" && (Mask & BIT_BDEV_FILE)) {
    Mask &= ~BIT_BDEV_FILE;
    Changed = true;
  }

  if (!Changed)
    return;

  if (Mask == 0) {
    State = State->remove<CloseNeedsNullMap>(BaseVD);
    State = State->remove<CloseOriginMap>(BaseVD);
  } else {
    State = State->set<CloseNeedsNullMap>(BaseVD, Mask);
  }

  C.addTransition(State);
}

// Pre-call: flag immediate uses of device->bdev_file (e.g., fput(device->bdev_file)) after close without NULL reset.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Only handle fput(ptr) here as a definite dereference use.
  if (!hasCalleeName(Call, "fput", C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg0 = Call.getArgExpr(0);
  const MemberExpr *ME = getMemberExprFrom(Arg0);
  if (!ME)
    return;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return;

  StringRef FieldName = getFieldNameFromFD(FD);
  if (FieldName != "bdev_file")
    return;

  const VarDecl *BaseVD = getBaseVarDeclOfExpr(ME->getBase());
  if (!BaseVD)
    return;

  ProgramStateRef State = C.getState();
  const unsigned *MaskPtr = State->get<CloseNeedsNullMap>(BaseVD);
  if (!MaskPtr)
    return;

  unsigned Mask = *MaskPtr;
  if (Mask & BIT_BDEV_FILE) {
    const Stmt *CloseSite = State->get<CloseOriginMap>(BaseVD);
    reportImmediateUseAfterClose(Call.getOriginExpr(), BaseVD, FieldName, CloseSite, C);
  }
}

// When 'if (device->bdev_file) ...' appears after close without NULL reset, warn about using freed pointer as flag.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(CondE);
  if (!ME)
    return;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return;

  StringRef FieldName = getFieldNameFromFD(FD);
  if (FieldName != "bdev_file")
    return;

  const VarDecl *BaseVD = getBaseVarDeclOfExpr(ME->getBase());
  if (!BaseVD)
    return;

  ProgramStateRef State = C.getState();
  const unsigned *MaskPtr = State->get<CloseNeedsNullMap>(BaseVD);
  if (!MaskPtr)
    return;

  unsigned Mask = *MaskPtr;
  if (Mask & BIT_BDEV_FILE) {
    const Stmt *CloseSite = State->get<CloseOriginMap>(BaseVD);
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Freed 'bdev_file' used as open-flag after close; reset it to NULL", N);
    R->addRange(Condition->getSourceRange());
    if (CloseSite)
      R->addNote("Closed here", CloseSite->getBeginLoc());
    C.emitReport(std::move(R));
  }
}

// At function end, if btrfs_close_bdev(device) was called but device->bdev_file wasn't set to NULL, report.
void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Iterate over entries
  auto Map = State->get<CloseNeedsNullMap>();
  for (auto It = Map.begin(); It != Map.end(); ++It) {
    const VarDecl *VD = It->first;
    unsigned Mask = It->second;

    if (Mask & BIT_BDEV_FILE) {
      const Stmt *CloseSite = State->get<CloseOriginMap>(VD);
      reportMissingNullAtEnd(VD, Mask, CloseSite, C);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects stale member pointer (e.g., bdev_file) not set to NULL after close, leading to UAF",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
