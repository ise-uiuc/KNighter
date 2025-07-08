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
#include "clang/AST/ASTContext.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Customized program state: map to track if the optlen parameter has been validated.
REGISTER_MAP_WITH_PROGRAMSTATE(ValidatedOptlenMap, const MemRegion*, bool)
// Optionally, you might want to track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// Helper to try to evaluate an expression to an integer.  Returns true on success.
static bool EvaluateExprToInt(llvm::APSInt &Result, const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  ProgramStateRef State = C.getState();
  SVal Val = State->getSVal(E, C.getLocationContext());
  // Try to see if the SVal is a concrete integer.
  if (!Val.isUnknownOrUndef()) {
    if (auto CI = Val.getAs<nonloc::ConcreteInt>()) {
      Result = CI->getValue();
      return true;
    }
  }
  return false;
}

/// Helper to retrieve the memory region associated with an expression.
static const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(E, C.getLocationContext());
  return SV.getAsRegion();
}

/// Helper to check whether an expression refers to an identifier with a given name.
static bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts()))
    return DRE->getDecl()->getNameAsString() == Name;
  return false;
}

/// Helper to recursively search for a specific type in the AST parent chain.
template <typename T>
static const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C) {
  // Use ASTContext's getParents interface.
  auto Parents = C.getASTContext().getParents(*S);
  for (const auto &Parent : Parents) {
    if (const T *Result = Parent.get<T>())
      return Result;
    if (const Stmt *ParentStmt = Parent.get<Stmt>())
      if (const T *Result = findSpecificTypeInParents<T>(ParentStmt, C))
        return Result;
  }
  return nullptr;
}

/// Helper to look upward in AST tree for a DeclRefExpr that has "optlen" in its name.
template <typename T>
const T* findOptlenInParents(const Stmt *S, CheckerContext &C) {
  return findSpecificTypeInParents<T>(S, C);
}

/// Helper function to determine whether the condition compares "optlen" against a constant.
/// It looks for binary operators with ">=".
static bool analyzeOptlenComparison(const Expr *CondE, CheckerContext &C, 
                                    long &ConstVal, const Expr *&OptlenExpr) {
  // Remove any parentheses and casts.
  CondE = CondE->IgnoreParenCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return false;
  // We only care about ">=" comparisons.
  if (BO->getOpcode() != BO_GE)
    return false;
  
  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  // Check if either side is named "optlen"
  bool LHSHasOptlen = ExprHasName(LHS, "optlen", C);
  bool RHSHasOptlen = ExprHasName(RHS, "optlen", C);
  
  // If neither operand is "optlen", we are not interested.
  if (!LHSHasOptlen && !RHSHasOptlen)
    return false;
  
  // Depending on which side is optlen, the other side should be a constant.
  const Expr *ConstExpr = nullptr;
  if (LHSHasOptlen) {
    OptlenExpr = LHS;
    ConstExpr = RHS;
  } else {
    OptlenExpr = RHS;
    ConstExpr = LHS;
  }

  llvm::APSInt EvalRes;
  // Try to evaluate the constant value.
  if (!EvaluateExprToInt(EvalRes, ConstExpr, C))
    return false;
  
  ConstVal = EvalRes.getExtValue();
  return true;
}

/// Helper function to update the ValidatedOptlenMap for a given memory region.
/// It also consults the alias map and updates the alias if available.
static ProgramStateRef markOptlenValidated(ProgramStateRef State, const MemRegion *MR) {
  if (!MR)
    return State;
  
  State = State->set<ValidatedOptlenMap>(MR, true);
  
  // Update the alias mapping if available.
  if (const MemRegion *const *AliasPtr = State->get<PtrAliasMap>(MR))
    State = State->set<ValidatedOptlenMap>(*AliasPtr, true);
  
  return State;
}

/// The main Checker class.
class SAGenTestChecker : public Checker<check::PreCall, check::BranchCondition, check::Bind> { 
   mutable std::unique_ptr<BugType> BT;

public:
   SAGenTestChecker() : BT(new BugType(this, "Unvalidated optlen with copy_from_sockptr")) {}

   // Callback when branch conditions are evaluated.
   void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
      ProgramStateRef State = C.getState();
      if (!Condition)
         return;
      
      const Expr *CondE = dyn_cast<Expr>(Condition);
      if (!CondE)
         return;
      
      // Only handle binary comparisons such as "optlen >= constant".
      long ConstVal = 0;
      const Expr *OptlenExpr = nullptr;
      if (!analyzeOptlenComparison(CondE, C, ConstVal, OptlenExpr))
         return;
      
      // For our bug, we expect the optlen to be at least a minimum copy size.
      // Here, we assume a minimum of 4 bytes.
      if (ConstVal < 4)
         return;
      
      // Retrieve the memory region corresponding to the optlen variable.
      const MemRegion *MR = getMemRegionFromExpr(OptlenExpr, C);
      if (!MR)
         return;
      
      MR = MR->getBaseRegion();
      if (!MR)
         return;
      
      // Mark this optlen as validated.
      State = markOptlenValidated(State, MR);
      
      C.addTransition(State);
   }
   
   // Callback before function calls are executed.
   void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
      ProgramStateRef State = C.getState();
      
      // Check if the call is to copy_from_sockptr.
      const Expr *OriginExpr = Call.getOriginExpr();
      if (!OriginExpr || !ExprHasName(OriginExpr, "copy_from_sockptr", C))
         return;
      
      // The expected number of bytes to copy is passed as the third argument.
      if (Call.getNumArgs() < 3)
         return;
      
      llvm::APSInt ExpectedCopyInt;
      if (!EvaluateExprToInt(ExpectedCopyInt, dyn_cast<Expr>(Call.getArgExpr(2)), C))
         return;
      
      long ExpectedCopyLen = ExpectedCopyInt.getExtValue();
      // Now attempt to locate an expression named "optlen" in the parent's AST.
      const DeclRefExpr *OptlenDRE = findOptlenInParents<DeclRefExpr>(OriginExpr, C);
      if (!OptlenDRE || !ExprHasName(OptlenDRE, "optlen", C))
         return;
      
      const MemRegion *OptlenMR = getMemRegionFromExpr(OptlenDRE, C);
      if (!OptlenMR)
         return;
      
      OptlenMR = OptlenMR->getBaseRegion();
      if (!OptlenMR)
         return;
      
      // Check if this optlen region has been validated.
      const bool *Validated = State->get<ValidatedOptlenMap>(OptlenMR);
      if (Validated && *Validated)
         return; // It is validated; no issue.
      
      // If not validated and the expected copy length is non-zero, report a bug.
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
         return;
      
      auto Report = std::make_unique<PathSensitiveBugReport>(
         *BT, "User buffer optlen not validated for copy_from_sockptr", N);
      Report->addRange(OriginExpr->getSourceRange());
      C.emitReport(std::move(Report));
   }
   
   // Callback to track aliasing of optlen parameters.
   void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
      ProgramStateRef State = C.getState();
      // If binding a value into a pointer, track potential aliasing.
      if (const MemRegion *LHSReg = Loc.getAsRegion()) {
         LHSReg = LHSReg->getBaseRegion();
         if (!LHSReg)
            return;
         if (const MemRegion *RHSReg = Val.getAsRegion()) {
            RHSReg = RHSReg->getBaseRegion();
            if (!RHSReg)
               return;
            // Record the aliasing: LHS points to RHS.
            State = State->set<PtrAliasMap>(LHSReg, RHSReg);
            State = State->set<PtrAliasMap>(RHSReg, LHSReg);
            C.addTransition(State);
         }
      }
   }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unvalidated user-supplied optlen in copy_from_sockptr usage", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
