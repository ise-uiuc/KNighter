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

// Additional includes required.
#include "clang/Lex/Lexer.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map that tracks which "optlen" regions have been validated.
REGISTER_MAP_WITH_PROGRAMSTATE(ValidatedOptlenMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker 
  : public Checker< check::PreCall,
                    check::BranchCondition,
                    check::Bind > {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() 
    : BT(new BugType(this, "User input length (optlen) not validated")) {}

  // Callback: check branch conditions to mark validated optlen.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  // Callback: check raw calls to copy_from_sockptr.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback: track pointer aliasing so that validated flags may propagate.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C, const MemRegion *OptlenRegion) const;
};

//
// checkBranchCondition: When a branch condition involves "optlen", and if it compares
// optlen with a constant that is at least as large as an expected size (e.g. sizeof(u32) == 4),
// mark the corresponding optlen region as validated.
//
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!Condition) {
    C.addTransition(State);
    return;
  }
  
  // We expect conditions to be expressions.
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }
  
  // Remove any parens and implicit casts.
  CondE = CondE->IgnoreParenCasts();
  
  // Use the provided utility function to check if the source text contains "optlen".
  if (ExprHasName(CondE, "optlen", C)) {
    // If we have a BinaryOperator comparing optlen against a constant,
    // check for operations like >=, >, or ==.
    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE)) {
      BinaryOperator::Opcode Op = BO->getOpcode();
      if (Op == BO_GE || Op == BO_GT || Op == BO_EQ) {
        // Identify which sub-expression is "optlen".
        const Expr *OptExpr = nullptr;
        if (ExprHasName(BO->getLHS(), "optlen", C))
          OptExpr = BO->getLHS();
        else if (ExprHasName(BO->getRHS(), "optlen", C))
          OptExpr = BO->getRHS();
        
        if (OptExpr) {
          const MemRegion *MR = getMemRegionFromExpr(OptExpr, C);
          if (MR) {
            MR = MR->getBaseRegion();
            // We perform a minimal check: if the condition compares optlen against a constant
            // at least 4 (i.e. sizeof(u32)), we assume validation is done.
            llvm::APSInt ConstVal;
            // Determine the other operand.
            const Expr *OtherOperand = nullptr;
            if (OptExpr == BO->getLHS())
              OtherOperand = BO->getRHS();
            else
              OtherOperand = BO->getLHS();
            if (OtherOperand && EvaluateExprToInt(ConstVal, OtherOperand, C)) {
              if (ConstVal.getLimitedValue() >= 4)
                State = State->set<ValidatedOptlenMap>(MR, true);
            }
          }
        }
      }
    }
    else {
      // If the condition text contains "optlen" and is not a binary operator, mark it validated.
      const MemRegion *MR = getMemRegionFromExpr(CondE, C);
      if (MR) {
        MR = MR->getBaseRegion();
        State = State->set<ValidatedOptlenMap>(MR, true);
      }
    }
  }
  C.addTransition(State);
}

//
// checkPreCall: Look for calls to copy_from_sockptr and then check if the
// user supplied optlen has been validated.
//
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Use the utility function to check the call expression text.
  if (!ExprHasName(OriginExpr, "copy_from_sockptr", C))
    return;
  
  // We have a call to copy_from_sockptr.
  // The bug pattern is in functions like rfcomm_sock_setsockopt or rfcomm_sock_setsockopt_old,
  // where the user-supplied length parameter "optlen" is expected (but must be validated).
  //
  // We try to find a parent DeclRefExpr that refers to "optlen".
  const DeclRefExpr *OptlenDRE = findSpecificTypeInParents<DeclRefExpr>(OriginExpr, C);
  if (!OptlenDRE)
    return;
  if (!ExprHasName(OptlenDRE, "optlen", C))
    return;
  
  // Retrieve the memory region corresponding to optlen.
  const MemRegion *OptlenRegion = getMemRegionFromExpr(OptlenDRE, C);
  if (!OptlenRegion)
    return;
  OptlenRegion = OptlenRegion->getBaseRegion();
  
  // Check if this region has been marked as validated.
  const bool *Validated = State->get<ValidatedOptlenMap>(OptlenRegion);
  if (!Validated || (*Validated == false)) {
    reportBug(Call, C, OptlenRegion);
  }
}

//
// checkBind: When a pointer is bound to another, if one (the right‐hand side)
// is marked as validated for optlen, then propagate that property to the left-hand side.
//
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  const MemRegion *RHSReg = Val.getAsRegion();
  if (!LHSReg || !RHSReg)
    return;
  
  LHSReg = LHSReg->getBaseRegion();
  RHSReg = RHSReg->getBaseRegion();
  if (!LHSReg || !RHSReg)
    return;
  
  // If the RHS region (which may represent "optlen") has been validated,
  // propagate that to the LHS.
  const bool *RHSValidated = State->get<ValidatedOptlenMap>(RHSReg);
  if (RHSValidated && *RHSValidated == true) {
    State = State->set<ValidatedOptlenMap>(LHSReg, true);
    C.addTransition(State);
    return;
  }
  C.addTransition(State);
}

//
// reportBug: Generate a non-fatal error node and emit a bug report.
//
void SAGenTestChecker::reportBug(const CallEvent &Call, CheckerContext &C,
                                 const MemRegion *OptlenRegion) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "User input length (optlen) not validated before copy_from_sockptr", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects raw use of copy_from_sockptr without validating user-supplied optlen", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
