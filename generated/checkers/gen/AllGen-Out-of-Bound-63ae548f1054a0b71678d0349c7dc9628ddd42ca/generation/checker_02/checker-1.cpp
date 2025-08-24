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
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed

namespace {

class SAGenTestChecker
  : public Checker<
        check::PreStmt<ArraySubscriptExpr>
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker()
        : BT(new BugType(this, "Index may exceed TRANSFER_FUNC_POINTS", "Array Bounds")) {}

      void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;

   private:
      // Helpers
      static bool baseIsTfPtsRGB(const Expr *Base, CheckerContext &C);
      static bool getIndexVarName(const Expr *IdxE, std::string &OutName);
      static bool stmtContains(const Stmt *Root, const Stmt *Target);
      static bool branchExits(const Stmt *S);
      static const Stmt* whichBranchContains(const IfStmt *If, const Stmt *Target);
      static bool condMentionsIdxAndTFP(const Expr *Cond, StringRef IdxName, CheckerContext &C);
      static bool hasDominatingGuard(const ArraySubscriptExpr *ASE, StringRef IdxName, CheckerContext &C);
};

bool SAGenTestChecker::baseIsTfPtsRGB(const Expr *Base, CheckerContext &C) {
  if (!Base)
    return false;

  Base = Base->IgnoreParenImpCasts();
  if (const auto *ME1 = dyn_cast<MemberExpr>(Base)) {
    const ValueDecl *VD1 = ME1->getMemberDecl();
    if (!VD1)
      return false;
    StringRef Name1 = VD1->getName();
    bool IsRGB = (Name1 == "red" || Name1 == "green" || Name1 == "blue");
    if (!IsRGB)
      return false;

    const Expr *B2 = ME1->getBase();
    if (!B2)
      return false;
    B2 = B2->IgnoreParenImpCasts();

    if (const auto *ME2 = dyn_cast<MemberExpr>(B2)) {
      const ValueDecl *VD2 = ME2->getMemberDecl();
      if (!VD2)
        return false;
      if (VD2->getName() == "tf_pts")
        return true;
    }
  }

  // Fallback heuristic: look for textual names
  if (ExprHasName(Base, "tf_pts", C) &&
      (ExprHasName(Base, "red", C) || ExprHasName(Base, "green", C) || ExprHasName(Base, "blue", C))) {
    return true;
  }

  return false;
}

bool SAGenTestChecker::getIndexVarName(const Expr *IdxE, std::string &OutName) {
  if (!IdxE)
    return false;
  IdxE = IdxE->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(IdxE)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      OutName = VD->getName().str();
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::stmtContains(const Stmt *Root, const Stmt *Target) {
  if (!Root || !Target)
    return false;
  if (Root == Target)
    return true;
  for (const Stmt *Child : Root->children()) {
    if (Child && stmtContains(Child, Target))
      return true;
  }
  return false;
}

bool SAGenTestChecker::branchExits(const Stmt *S) {
  if (!S)
    return false;
  if (isa<ReturnStmt>(S) || isa<BreakStmt>(S))
    return true;

  // Also consider 'if' branches that exit, and nested structures.
  for (const Stmt *Child : S->children()) {
    if (Child && branchExits(Child))
      return true;
  }
  return false;
}

// Returns pointer to the branch (Then or Else) that contains Target, or nullptr if neither.
const Stmt* SAGenTestChecker::whichBranchContains(const IfStmt *If, const Stmt *Target) {
  if (!If || !Target)
    return nullptr;

  const Stmt *ThenS = If->getThen();
  const Stmt *ElseS = If->getElse();

  if (ThenS && stmtContains(ThenS, Target))
    return ThenS;
  if (ElseS && stmtContains(ElseS, Target))
    return ElseS;

  return nullptr;
}

bool SAGenTestChecker::condMentionsIdxAndTFP(const Expr *Cond, StringRef IdxName, CheckerContext &C) {
  if (!Cond)
    return false;
  // Check the textual presence of both the index variable and TRANSFER_FUNC_POINTS
  if (!ExprHasName(Cond, IdxName, C))
    return false;
  if (!ExprHasName(Cond, "TRANSFER_FUNC_POINTS", C))
    return false;
  return true;
}

bool SAGenTestChecker::hasDominatingGuard(const ArraySubscriptExpr *ASE, StringRef IdxName, CheckerContext &C) {
  if (!ASE)
    return false;

  // Find the nearest enclosing compound statement
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(ASE, C);
  if (!CS)
    return false;

  // Materialize the body statements into an indexable container.
  llvm::SmallVector<const Stmt *, 16> BodyStmts;
  for (const Stmt *S : CS->body())
    BodyStmts.push_back(S);

  // Find the top-level statement inside CS that contains ASE
  int P = -1;
  const Stmt *TopStmt = nullptr;
  for (size_t i = 0; i < BodyStmts.size(); ++i) {
    const Stmt *Child = BodyStmts[i];
    if (!Child)
      continue;
    if (stmtContains(Child, ASE)) {
      P = static_cast<int>(i);
      TopStmt = Child;
      break;
    }
  }

  if (P == -1 || !TopStmt)
    return false;

  // Case A: The containing top-level statement itself is an IfStmt, and it encloses the access.
  if (const auto *If = dyn_cast<IfStmt>(TopStmt)) {
    // If the condition mentions index and TRANSFER_FUNC_POINTS, and the opposite branch exits -> treated as a guard.
    const Stmt *ContainingBranch = whichBranchContains(If, ASE);
    if (ContainingBranch) {
      const Expr *Cond = If->getCond();
      if (condMentionsIdxAndTFP(Cond, IdxName, C)) {
        const Stmt *OtherBranch = (ContainingBranch == If->getThen()) ? If->getElse() : If->getThen();
        if (OtherBranch && branchExits(OtherBranch))
          return true;
      }
    }
  }

  // Case B: Scan previous sibling statements in the same compound for a guard if-statement.
  for (int pi = P - 1; pi >= 0; --pi) {
    const Stmt *Prev = BodyStmts[static_cast<size_t>(pi)];
    if (!Prev)
      continue;

    const auto *If = dyn_cast<IfStmt>(Prev);
    if (!If)
      continue;

    const Expr *Cond = If->getCond();
    if (!condMentionsIdxAndTFP(Cond, IdxName, C))
      continue;

    // If either branch exits, treat this as a guarding check.
    const Stmt *ThenS = If->getThen();
    const Stmt *ElseS = If->getElse();
    if ((ThenS && branchExits(ThenS)) || (ElseS && branchExits(ElseS)))
      return true;
  }

  return false;
}

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
  if (!ASE)
    return;

  const Expr *Base = ASE->getBase();
  if (!Base)
    return;

  // Match output_tf->tf_pts.{red,green,blue}[i]
  if (!baseIsTfPtsRGB(Base, C))
    return;

  // Extract index variable name
  const Expr *IdxE = ASE->getIdx();
  std::string IdxName;
  if (!getIndexVarName(IdxE, IdxName))
    return;

  // Check for a dominating guard that compares index with TRANSFER_FUNC_POINTS and exits
  if (hasDominatingGuard(ASE, IdxName, C))
    return;

  // No guard found: report potential OOB
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Index may exceed TRANSFER_FUNC_POINTS when indexing LUT array", N);
  SourceRange R = ASE->getSourceRange();
  Report->addRange(R);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects LUT array indexing without validating index against TRANSFER_FUNC_POINTS",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
