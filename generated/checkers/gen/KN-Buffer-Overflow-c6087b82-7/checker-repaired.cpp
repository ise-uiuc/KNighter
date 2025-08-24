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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps:
// - PtrAliasMap: map a pointer variable region to the base region it ultimately aliases.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
// - UnboundedCopyMap: mark base array regions that had an unsafe/unbounded copy_from_user into them.
REGISTER_MAP_WITH_PROGRAMSTATE(UnboundedCopyMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker
  : public Checker<check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded user copy into fixed buffer", "Security")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      bool isCopyFromUser(const CallEvent &Call, CheckerContext &C) const;
      bool isStringOp(const CallEvent &Call, CheckerContext &C) const;

      const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      bool getArraySizeForDestExpr(const Expr *DestE, llvm::APInt &ArrSz,
                                   CheckerContext &C) const;

      bool getUpperBoundOfSizeArg(const Expr *SizeE, CheckerContext &C,
                                  llvm::APSInt &UB, bool &Known) const;

      const MemRegion *getArrayBaseForArg(const Expr *ArgE, CheckerContext &C) const;

      void reportCopyIssue(const CallEvent &Call, CheckerContext &C) const;
      void reportStringUseIssue(const CallEvent &Call, CheckerContext &C) const;
};

// Return true if the call is to copy_from_user.
bool SAGenTestChecker::isCopyFromUser(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "copy_from_user", C);
}

// Return true if the call is one of common string operations that expect NUL-terminated strings.
bool SAGenTestChecker::isStringOp(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // String ops to consider.
  static const char *Names[] = {
    "strcmp", "strncmp", "strcasecmp", "strncasecmp", "strlen"
  };
  for (const char *N : Names) {
    if (ExprHasName(Origin, N, C))
      return true;
  }
  return false;
}

// Get the base region from an expression using the analyzer's SVal machinery.
// Do not IgnoreImplicit() before calling getMemRegionFromExpr, and always normalize to base region.
const MemRegion *SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

// Try to infer the constant array size for a destination expression.
// Returns true on success and stores the size into ArrSz.
bool SAGenTestChecker::getArraySizeForDestExpr(const Expr *DestE, llvm::APInt &ArrSz,
                                               CheckerContext &C) const {
  if (!DestE)
    return false;

  // First, if the expression itself is a DeclRefExpr, try directly.
  if (const auto *DREself = dyn_cast<DeclRefExpr>(DestE->IgnoreParenCasts())) {
    if (getArraySizeFromExpr(ArrSz, DREself))
      return true;
  }

  // Otherwise, try to find a DeclRefExpr in the children (works for array-to-pointer decay or &buf[0], etc).
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(DestE)) {
    if (getArraySizeFromExpr(ArrSz, DRE))
      return true;
  }

  return false;
}

// Infer an upper bound for the size argument.
// Known is set to true if UB is a known constant/upper bound. Otherwise, Known is false.
bool SAGenTestChecker::getUpperBoundOfSizeArg(const Expr *SizeE, CheckerContext &C,
                                              llvm::APSInt &UB, bool &Known) const {
  Known = false;
  if (!SizeE)
    return false;

  // Try to evaluate as integer constant
  if (EvaluateExprToInt(UB, SizeE, C)) {
    Known = true;
    return true;
  }

  // Otherwise, try to infer max value via symbol constraints.
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(SizeE, C.getLocationContext());
  SymbolRef Sym = SV.getAsSymbol();
  if (!Sym)
    return false;

  if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
    UB = *MaxV;
    Known = true;
    return true;
  }

  return false;
}

// Given an argument expression to a string function, get the base array region it refers to.
// This consults alias map to resolve pointer variables.
const MemRegion *SAGenTestChecker::getArrayBaseForArg(const Expr *ArgE, CheckerContext &C) const {
  if (!ArgE)
    return nullptr;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getBaseRegionFromExpr(ArgE, C);
  if (!MR)
    return nullptr;

  // If the expression is a pointer variable that aliases an array, resolve it through PtrAliasMap.
  if (const MemRegion * const *AliasedBase = State->get<PtrAliasMap>(MR)) {
    return *AliasedBase;
  }

  // Otherwise, return the base we got. This may already be the array's VarRegion.
  return MR;
}

// Report at copy_from_user callsite: potential overflow and missing min(..., sizeof-1).
void SAGenTestChecker::reportCopyIssue(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_from_user size may exceed destination; cap to min(n, sizeof(buf)-1).", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

// Report at string operation callsite after an unsafe copy.
void SAGenTestChecker::reportStringUseIssue(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "String function on buffer after unbounded copy_from_user; missing NUL and overflow risk.", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

// Handle calls: detect unsafe copy_from_user and later string ops.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Case 1: copy_from_user(dst, src, nbytes)
  if (isCopyFromUser(Call, C)) {
    const Expr *DestE = Call.getArgExpr(0);
    const Expr *SizeE = Call.getArgExpr(2);
    if (!DestE || !SizeE)
      return;

    // We only warn when destination is a fixed-size array known at compile time.
    llvm::APInt ArrSz;
    if (!getArraySizeForDestExpr(DestE, ArrSz, C))
      return;

    const MemRegion *BaseR = getBaseRegionFromExpr(DestE, C);
    if (!BaseR)
      return;

    // Compute limit = sizeof(array) - 1
    if (ArrSz == 0)
      return; // degenerate
    llvm::APInt LimitAP = ArrSz;
    LimitAP -= 1;

    llvm::APSInt UB;
    bool Known = false;
    getUpperBoundOfSizeArg(SizeE, C, UB, Known);

    bool Safe = false;
    if (Known) {
      uint64_t ubVal = UB.getLimitedValue(UINT64_MAX);
      uint64_t limitVal = LimitAP.getLimitedValue(UINT64_MAX);
      Safe = (ubVal <= limitVal);
    }

    if (Safe) {
      // Clear any previous unsafe mark for this base region.
      State = State->remove<UnboundedCopyMap>(BaseR);
      C.addTransition(State);
    } else {
      // Mark as unsafe and report.
      State = State->set<UnboundedCopyMap>(BaseR, true);
      C.addTransition(State);
      reportCopyIssue(Call, C);
    }
    return;
  }

  // Case 2: string operations: strcmp/strncmp/strcasecmp/strncasecmp/strlen
  if (isStringOp(Call, C)) {
    if (Call.getNumArgs() == 0)
      return;

    const Expr *Arg0 = Call.getArgExpr(0);
    const MemRegion *BaseR = getArrayBaseForArg(Arg0, C);
    if (!BaseR)
      return;

    const bool *Flag = State->get<UnboundedCopyMap>(BaseR);
    if (Flag && *Flag) {
      reportStringUseIssue(Call, C);
    }
    return;
  }
}

// Track pointer aliases so that p = &buf[0]; and later string ops on p can be recognized.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }

  // Only track pointer-like values mapping to an underlying base region.
  const MemRegion *RHSReg = Val.getAsRegion();
  const MemRegion *BaseToStore = nullptr;

  if (RHSReg) {
    RHSReg = RHSReg->getBaseRegion();
    if (RHSReg) {
      // If RHS is a pointer variable with an existing mapping, reuse it.
      if (const MemRegion * const *Aliased = State->get<PtrAliasMap>(RHSReg)) {
        BaseToStore = *Aliased;
      } else {
        // Otherwise, store its own base region (might be an array's VarRegion or similar).
        BaseToStore = RHSReg;
      }
    }
  }

  if (BaseToStore) {
    State = State->set<PtrAliasMap>(LHSReg, BaseToStore);
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded copy_from_user into fixed-size buffers and subsequent string use without guaranteed NUL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
