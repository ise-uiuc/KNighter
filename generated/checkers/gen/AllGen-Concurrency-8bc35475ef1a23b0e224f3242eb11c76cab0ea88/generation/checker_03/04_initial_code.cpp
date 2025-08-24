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
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Spurious data-race: read before guard",
                       "Concurrency")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper: find first reference to a VarDecl within an expression.
  const VarDecl *findFirstVarDeclUse(const Expr *E) const;

  // Helper: whether the expression contains a reference to a specific VarDecl.
  bool exprContainsVarRef(const Expr *E, const VarDecl *VD) const;

  // Helper: get the previous statement (sibling) before 'S' inside 'CS'.
  const Stmt *getPrevSiblingStmt(const Stmt *S, const CompoundStmt *CS) const;

  // Helper: From a previous statement, try to extract an assignment/initializer
  // that writes to the given VarDecl. If found, set EOut to the RHS/init expr.
  bool extractExprAssignedToVarFromPrev(const Stmt *Prev, const VarDecl *VD,
                                        const Expr *&EOut) const;

  // Heuristic: does E look like a non-atomic shared-field read (e.g. *work_data_bits(work), ->data)?
  bool looksLikeSharedFieldRead(const Expr *E, CheckerContext &C) const;

  // Heuristic: is the left side of && a guard (e.g., from_cancel), or are we
  // in a function with name containing "flush_work"?
  bool isGuardOrFlushWorkContext(const Expr *LHS, const IfStmt *IS,
                                 CheckerContext &C) const;

  // Utility: find a MemberExpr child and check if its member name equals "data".
  bool containsMemberNamedData(const Expr *E) const;

  // Utility: find a dereference operator in expression.
  bool containsDeref(const Expr *E) const;
};

// -------------------- Helper implementations --------------------

const VarDecl *SAGenTestChecker::findFirstVarDeclUse(const Expr *E) const {
  if (!E)
    return nullptr;

  class Visitor : public RecursiveASTVisitor<Visitor> {
  public:
    const VarDecl *Result = nullptr;

    bool VisitDeclRefExpr(const DeclRefExpr *DRE) {
      if (!Result) {
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          Result = VD;
          return false; // stop traversal
        }
      }
      return true;
    }
  } V;

  // We need a non-const Stmt* for the visitor's TraverseStmt.
  const_cast<Expr *>(E)->IgnoreParenImpCasts();
  V.TraverseStmt(const_cast<Expr *>(E));
  return V.Result;
}

bool SAGenTestChecker::exprContainsVarRef(const Expr *E,
                                          const VarDecl *Target) const {
  if (!E || !Target)
    return false;

  class Visitor : public RecursiveASTVisitor<Visitor> {
  public:
    const VarDecl *Target = nullptr;
    bool Found = false;

    bool VisitDeclRefExpr(const DeclRefExpr *DRE) {
      if (Found)
        return false;
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (VD == Target) {
          Found = true;
          return false;
        }
      }
      return true;
    }
  } V;

  V.Target = Target;
  V.TraverseStmt(const_cast<Expr *>(E));
  return V.Found;
}

const Stmt *SAGenTestChecker::getPrevSiblingStmt(const Stmt *S,
                                                 const CompoundStmt *CS) const {
  if (!S || !CS)
    return nullptr;

  const Stmt *Prev = nullptr;
  for (const Stmt *Child : CS->body()) {
    if (Child == S)
      return Prev;
    Prev = Child;
  }
  return nullptr;
}

bool SAGenTestChecker::extractExprAssignedToVarFromPrev(const Stmt *Prev,
                                                        const VarDecl *VD,
                                                        const Expr *&EOut) const {
  EOut = nullptr;
  if (!Prev || !VD)
    return false;

  // Case 1: V = E;  (BinaryOperator assignment)
  if (const auto *BO = dyn_cast<BinaryOperator>(Prev)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == VD) {
          EOut = BO->getRHS()->IgnoreParenImpCasts();
          return EOut != nullptr;
        }
      }
    }
  }

  // Case 2: type V = E; (DeclStmt with initializer)
  if (const auto *DS = dyn_cast<DeclStmt>(Prev)) {
    if (DS->isSingleDecl()) {
      if (const auto *D = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        if (D == VD) {
          if (const Expr *Init = D->getInit()) {
            EOut = Init->IgnoreParenImpCasts();
            return EOut != nullptr;
          }
        }
      }
    }
  }

  return false;
}

bool SAGenTestChecker::containsMemberNamedData(const Expr *E) const {
  if (!E)
    return false;

  class Visitor : public RecursiveASTVisitor<Visitor> {
  public:
    bool Found = false;
    bool VisitMemberExpr(const MemberExpr *ME) {
      if (Found)
        return false;
      if (ME->getMemberNameInfo().getAsString() == "data") {
        Found = true;
        return false;
      }
      return true;
    }
  } V;

  V.TraverseStmt(const_cast<Expr *>(E));
  return V.Found;
}

bool SAGenTestChecker::containsDeref(const Expr *E) const {
  if (!E)
    return false;

  class Visitor : public RecursiveASTVisitor<Visitor> {
  public:
    bool Found = false;
    bool VisitUnaryOperator(const UnaryOperator *UO) {
      if (Found)
        return false;
      if (UO->getOpcode() == UO_Deref) {
        Found = true;
        return false;
      }
      return true;
    }
  } V;

  V.TraverseStmt(const_cast<Expr *>(E));
  return V.Found;
}

bool SAGenTestChecker::looksLikeSharedFieldRead(const Expr *E,
                                                CheckerContext &C) const {
  if (!E)
    return false;

  // Exclude known-safe atomic/qualified reads to limit false positives.
  if (ExprHasName(E, "READ_ONCE", C) || ExprHasName(E, "atomic", C) ||
      ExprHasName(E, "smp_load", C))
    return false;

  // Direct name heuristics.
  if (ExprHasName(E, "work_data_bits", C) || ExprHasName(E, "->data", C) ||
      ExprHasName(E, ".data", C))
    return true;

  // Structural heuristics.
  if (containsMemberNamedData(E))
    return true;

  if (containsDeref(E))
    return true;

  return false;
}

bool SAGenTestChecker::isGuardOrFlushWorkContext(const Expr *LHS,
                                                 const IfStmt *IS,
                                                 CheckerContext &C) const {
  if (!IS)
    return false;

  // If LHS contains "cancel" (as in from_cancel), treat it as a guard.
  if (LHS && ExprHasName(LHS, "cancel", C))
    return true;

  // Otherwise allow in functions with names containing "flush_work".
  const FunctionDecl *FD = findSpecificTypeInParents<FunctionDecl>(IS, C);
  if (FD) {
    std::string Name = FD->getNameAsString();
    if (Name.find("flush_work") != std::string::npos)
      return true;
  }

  return false;
}

// -------------------- Main check --------------------

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  // Ensure we are in an if-statement condition.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  // We only target conditions of the form (LHS && RHS).
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO || BO->getOpcode() != BO_LAnd)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  // Heuristically confirm LHS looks like a guard (from_cancel) or we're in
  // a flush_work-like context.
  if (!isGuardOrFlushWorkContext(LHS, IS, C))
    return;

  // Find a variable used on the RHS (e.g., "data").
  const VarDecl *UsedVar = findFirstVarDeclUse(RHS);
  if (!UsedVar)
    return;

  // Ensure the LHS (guard) does not reference the same variable.
  if (exprContainsVarRef(LHS, UsedVar))
    return;

  // Locate the previous statement in the same compound block.
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!CS)
    return;

  const Stmt *Prev = getPrevSiblingStmt(IS, CS);
  if (!Prev)
    return;

  // From the previous statement, extract an expression that assigns to UsedVar.
  const Expr *PrevReadExpr = nullptr;
  if (!extractExprAssignedToVarFromPrev(Prev, UsedVar, PrevReadExpr))
    return;

  // The previous expression must look like an unsafe shared-field read.
  if (!looksLikeSharedFieldRead(PrevReadExpr, C))
    return;

  // All checks passed: report the issue.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unconditional read of shared field before guard; move the read under the if (guard).",
      N);

  // Highlight the previous read statement or the expression.
  if (PrevReadExpr)
    R->addRange(PrevReadExpr->getSourceRange());
  else
    R->addRange(Prev->getSourceRange());

  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unconditional shared-field reads moved before a guarding condition (spurious data-race)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
