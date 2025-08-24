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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are necessary.

namespace {

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Off-by-one bounds check", "Logic error")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Find a strict upper bound comparison inside Cond of the form:
      //   idx > MAX   or   MAX < idx
      // Returns true and fills OutIdxVar, OutBound, OutOp if found.
      bool findStrictUpperBound(const Expr *Cond,
                                const VarDecl *&OutIdxVar,
                                llvm::APSInt &OutBound,
                                const BinaryOperator *&OutOp,
                                ASTContext &AC) const;

      // Analyze a single IfStmt:
      //  - must have early return in then-branch
      //  - must contain strict upper bound check on an index
      //  - later array subscript with same index into array of size == bound
      void analyzeIfStmt(const IfStmt *IfS,
                         const Stmt *FuncBody,
                         ASTContext &AC,
                         AnalysisManager &Mgr,
                         BugReporter &BR) const;

      // Recursively visit all IfStmts in function body.
      void visitIfs(const Stmt *S,
                    const Stmt *FuncBody,
                    ASTContext &AC,
                    AnalysisManager &Mgr,
                    BugReporter &BR) const;

      // Extract constant array size from base expression of an array access.
      bool getArraySizeFromBaseExpr(const Expr *BaseE, llvm::APInt &ArraySize) const;

      // Check whether expression E refers to the same variable Var (DeclRefExpr).
      bool isExprRefToVar(const Expr *E, const VarDecl *Var) const;
};

bool SAGenTestChecker::isExprRefToVar(const Expr *E, const VarDecl *Var) const {
  if (!E || !Var) return false;
  const Expr *IE = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(IE)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD == Var;
  }
  return false;
}

bool SAGenTestChecker::getArraySizeFromBaseExpr(const Expr *BaseE, llvm::APInt &ArraySize) const {
  if (!BaseE) return false;
  const Expr *BE = BaseE->IgnoreParenImpCasts();

  // Case 1: DeclRefExpr to a VarDecl with constant array type
  if (const auto *DRE = dyn_cast<DeclRefExpr>(BE)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = CAT->getSize();
        return true;
      }
    }
  }

  // Case 2: MemberExpr to a FieldDecl with constant array type (e.g., adc->thresholds[...])
  if (const auto *ME = dyn_cast<MemberExpr>(BE)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      QualType FT = FD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(FT.getTypePtr())) {
        ArraySize = CAT->getSize();
        return true;
      }
    }
  }

  return false;
}

bool SAGenTestChecker::findStrictUpperBound(const Expr *Cond,
                                            const VarDecl *&OutIdxVar,
                                            llvm::APSInt &OutBound,
                                            const BinaryOperator *&OutOp,
                                            ASTContext &AC) const {
  if (!Cond) return false;
  const Expr *E = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    // Direct match: idx > MAX
    if (BO->getOpcode() == BO_GT) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      if (const auto *LDRE = dyn_cast<DeclRefExpr>(L)) {
        if (const auto *VD = dyn_cast<VarDecl>(LDRE->getDecl())) {
          Expr::EvalResult ER;
          if (R->EvaluateAsInt(ER, AC)) {
            OutIdxVar = VD;
            OutBound = ER.Val.getInt();
            OutOp = BO;
            return true;
          }
        }
      }
    }

    // Direct match: MAX < idx
    if (BO->getOpcode() == BO_LT) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      Expr::EvalResult ER;
      if (L->EvaluateAsInt(ER, AC)) {
        if (const auto *RDRE = dyn_cast<DeclRefExpr>(R)) {
          if (const auto *VD = dyn_cast<VarDecl>(RDRE->getDecl())) {
            OutIdxVar = VD;
            OutBound = ER.Val.getInt();
            OutOp = BO;
            return true;
          }
        }
      }
    }

    // Otherwise, recurse into both sides (handles logical ops like ||, &&, etc.)
    if (findStrictUpperBound(BO->getLHS(), OutIdxVar, OutBound, OutOp, AC))
      return true;
    if (findStrictUpperBound(BO->getRHS(), OutIdxVar, OutBound, OutOp, AC))
      return true;

    return false;
  }

  // Generic recursion over children for other expression kinds.
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child)) {
      if (findStrictUpperBound(CE, OutIdxVar, OutBound, OutOp, AC))
        return true;
    }
  }

  return false;
}

void SAGenTestChecker::analyzeIfStmt(const IfStmt *IfS,
                                     const Stmt *FuncBody,
                                     ASTContext &AC,
                                     AnalysisManager &Mgr,
                                     BugReporter &BR) const {
  if (!IfS || !FuncBody) return;

  // Heuristic: require early return in the 'then' branch
  const Stmt *ThenS = IfS->getThen();
  if (!ThenS)
    return;

  // Use the provided utility to find ReturnStmt in 'then'
  const ReturnStmt *RetInThen = findSpecificTypeInChildren<ReturnStmt>(ThenS);
  if (!RetInThen)
    return;

  // Find the strict upper bound in the condition
  const VarDecl *IdxVar = nullptr;
  llvm::APSInt Bound;
  const BinaryOperator *OpNode = nullptr;

  const Expr *Cond = IfS->getCond();
  if (!Cond)
    return;

  if (!findStrictUpperBound(Cond, IdxVar, Bound, OpNode, AC))
    return;

  // After the IfStmt, look for array subscripts A[IdxVar]
  const SourceManager &SM = Mgr.getSourceManager();
  SourceLocation IfLoc = SM.getFileLoc(IfS->getIfLoc());

  // Traverse function body and search for ArraySubscriptExpr after IfLoc
  bool Reported = false;

  std::function<void(const Stmt *)> Walker = [&](const Stmt *S) {
    if (!S || Reported) return;

    // Check for array subscript
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
      SourceLocation ASELoc = SM.getFileLoc(ASE->getExprLoc());
      if (SM.isBeforeInTranslationUnit(IfLoc, ASELoc)) {
        // Index should reference the same variable
        const Expr *IdxE = ASE->getIdx();
        if (isExprRefToVar(IdxE, IdxVar)) {
          // Determine array size from base expression
          llvm::APInt ArrSize;
          if (getArraySizeFromBaseExpr(ASE->getBase(), ArrSize)) {
            // Compare ArrSize with Bound
            uint64_t ArrVal = ArrSize.getLimitedValue(UINT64_MAX);
            uint64_t BoundVal = Bound.isSigned()
                                    ? static_cast<uint64_t>(static_cast<int64_t>(Bound.getSExtValue()))
                                    : Bound.getZExtValue();

            if (ArrVal == BoundVal) {
              // Off-by-one: using '>' or '<' allows idx == MAX; should use '>=' or '<=' respectively.
              SourceLocation Loc = OpNode ? OpNode->getOperatorLoc() : IfS->getIfLoc();
              auto R = std::make_unique<BasicBugReport>(
                  *BT,
                  "Off-by-one bound check: '>' allows index == bound; use '>='",
                  PathDiagnosticLocation(Loc, BR.getSourceManager()));
              R->addRange(OpNode ? OpNode->getSourceRange() : IfS->getSourceRange());
              BR.emitReport(std::move(R));
              Reported = true;
              return;
            }
          }
        }
      }
    }

    for (const Stmt *Child : S->children())
      Walker(Child);
  };

  Walker(FuncBody);
}

void SAGenTestChecker::visitIfs(const Stmt *S,
                                const Stmt *FuncBody,
                                ASTContext &AC,
                                AnalysisManager &Mgr,
                                BugReporter &BR) const {
  if (!S) return;

  if (const auto *IfS = dyn_cast<IfStmt>(S))
    analyzeIfStmt(IfS, FuncBody, AC, Mgr, BR);

  for (const Stmt *Child : S->children())
    visitIfs(Child, FuncBody, AC, Mgr, BR);
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &AC = Mgr.getASTContext();
  visitIfs(Body, Body, AC, Mgr, BR);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects off-by-one array index checks that use '>' instead of '>=' when guarding array accesses",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
