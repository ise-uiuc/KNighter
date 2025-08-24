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
#include "clang/Lex/Lexer.h"
#include <vector>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are necessary.

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Speculative read before guard", "Concurrency")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper: flatten a top-level chain of logical-and (&&) into ordered conjuncts.
  static void collectAndConjuncts(const Expr *E,
                                  llvm::SmallVector<const Expr *, 8> &Out);
  // Helper: find the IfStmt enclosing the given condition.
  static const IfStmt *getEnclosingIf(const Stmt *S, CheckerContext &C);

  // Helper: find the immediately preceding non-empty statement of the IfStmt
  // within its parent compound statement.
  static const Stmt *findPrevNonEmptyStmt(const IfStmt *IS, CheckerContext &C);

  // Helper: determine whether an expression represents an unsafe early read
  // of work->data (directly or via *work_data_bits(work)), without READ_ONCE-like
  // qualifiers.
  static bool isUnsafeEarlyReadExpr(const Expr *E, CheckerContext &C);

  // Helper: check whether an expression uses a given VarDecl via DeclRefExpr.
  static bool exprUsesVar(const Expr *E, const VarDecl *VD);

  // Helper: check whether any conjunct (from StartIdx onward) uses a given VarDecl.
  static bool varUsedInConjuncts(const llvm::SmallVector<const Expr *, 8> &Conj,
                                 unsigned StartIdx, const VarDecl *VD);

  // Helper: simple filter to ensure RHS conjuncts look related to the shared field.
  static bool rhsConjunctsMentionShared(
      const llvm::SmallVector<const Expr *, 8> &Conj, unsigned StartIdx,
      CheckerContext &C);
};

//------------------------------------------------------------------------------
// Collect logical-and conjuncts (left-to-right).
//------------------------------------------------------------------------------
void SAGenTestChecker::collectAndConjuncts(const Expr *E,
                                           llvm::SmallVector<const Expr *, 8> &Out) {
  if (!E)
    return;
  E = E->IgnoreParenCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      collectAndConjuncts(BO->getLHS(), Out);
      collectAndConjuncts(BO->getRHS(), Out);
      return;
    }
  }
  Out.push_back(E);
}

const IfStmt *SAGenTestChecker::getEnclosingIf(const Stmt *S, CheckerContext &C) {
  return findSpecificTypeInParents<IfStmt>(S, C);
}

const Stmt *SAGenTestChecker::findPrevNonEmptyStmt(const IfStmt *IS,
                                                   CheckerContext &C) {
  if (!IS)
    return nullptr;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(
      dyn_cast<Stmt>(IS), C);
  if (!CS)
    return nullptr;

  const Stmt *Prev = nullptr;
  for (const Stmt *Child : CS->body()) {
    if (Child == IS)
      break;
    // Skip null statements (semi-colons) if any
    if (!Child)
      continue;
    if (isa<NullStmt>(Child))
      continue;
    Prev = Child;
  }
  return Prev;
}

bool SAGenTestChecker::isUnsafeEarlyReadExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  // Reject if access is qualified as safe.
  if (ExprHasName(E, "READ_ONCE", C) ||
      ExprHasName(E, "ACCESS_ONCE", C) ||
      ExprHasName(E, "smp_load_acquire", C)) {
    return false;
  }

  const Expr *EI = E->IgnoreParenCasts();

  // Pattern A: *work_data_bits(work)
  if (const auto *UO = dyn_cast<UnaryOperator>(EI)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      if (const auto *CE = dyn_cast<CallExpr>(SubE)) {
        const Expr *Callee = CE->getCallee();
        if (Callee && ExprHasName(Callee, "work_data_bits", C)) {
          return true;
        }
      }
      // Fallback textual check for robustness
      if (ExprHasName(SubE, "work_data_bits", C))
        return true;
    }
  }
  // Textual pattern check: read via accessor call
  if (ExprHasName(EI, "work_data_bits", C))
    return true;

  // Pattern B: direct field access like work->data or work.data
  bool mentionsWork = ExprHasName(EI, "work", C);
  bool mentionsArrowData = ExprHasName(EI, "->data", C);
  bool mentionsDotData = ExprHasName(EI, ".data", C);
  if (mentionsWork && (mentionsArrowData || mentionsDotData))
    return true;

  return false;
}

bool SAGenTestChecker::exprUsesVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;

  struct Finder : public RecursiveASTVisitor<Finder> {
    const VarDecl *Target;
    bool Found = false;
    explicit Finder(const VarDecl *VD) : Target(VD) {}
    bool VisitDeclRefExpr(DeclRefExpr *DRE) {
      if (const auto *V = dyn_cast_or_null<VarDecl>(DRE->getDecl())) {
        if (V == Target) {
          Found = true;
          return false; // Stop early
        }
      }
      return true;
    }
  };

  Finder F(VD);
  F.TraverseStmt(const_cast<Expr *>(E));
  return F.Found;
}

bool SAGenTestChecker::varUsedInConjuncts(
    const llvm::SmallVector<const Expr *, 8> &Conj, unsigned StartIdx,
    const VarDecl *VD) {
  for (unsigned i = StartIdx; i < Conj.size(); ++i) {
    if (exprUsesVar(Conj[i], VD))
      return true;
  }
  return false;
}

bool SAGenTestChecker::rhsConjunctsMentionShared(
    const llvm::SmallVector<const Expr *, 8> &Conj, unsigned StartIdx,
    CheckerContext &C) {
  for (unsigned i = StartIdx; i < Conj.size(); ++i) {
    const Expr *E = Conj[i];
    if (!E)
      continue;
    if (ExprHasName(E, "work_data_bits", C))
      return true;
    if (ExprHasName(E, "->data", C))
      return true;
    if (ExprHasName(E, ".data", C))
      return true;
    if (ExprHasName(E, "data", C))
      return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// Main detection in branch conditions.
//------------------------------------------------------------------------------
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  // Find the enclosing if-statement for this condition.
  const IfStmt *IS = getEnclosingIf(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(IS->getCond());
  if (!CondE)
    return;

  llvm::SmallVector<const Expr *, 8> Conj;
  collectAndConjuncts(CondE, Conj);
  if (Conj.size() < 2)
    return;

  // Guard must be the leftmost conjunct and mention "from_cancel".
  const Expr *Guard = Conj[0];
  if (!Guard || !ExprHasName(Guard, "from_cancel", C))
    return;

  // Heuristic check that RHS conjuncts talk about the shared field.
  if (!rhsConjunctsMentionShared(Conj, /*StartIdx=*/1, C))
    return;

  // Look for an immediately preceding unconditional read.
  const Stmt *Prev = findPrevNonEmptyStmt(IS, C);
  if (!Prev)
    return;

  // Case 1: DeclStmt with single VarDecl and initializer
  if (const auto *DS = dyn_cast<DeclStmt>(Prev)) {
    if (DS->isSingleDecl()) {
      if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        if (VD->hasInit()) {
          const Expr *Init = VD->getInit();
          if (isUnsafeEarlyReadExpr(Init, C)) {
            // Ensure that this variable feeds into RHS conjuncts.
            if (varUsedInConjuncts(Conj, /*StartIdx=*/1, VD)) {
              ExplodedNode *N = C.generateNonFatalErrorNode();
              if (!N)
                return;
              auto R = std::make_unique<PathSensitiveBugReport>(
                  *BT,
                  "Early read of work->data before checking from_cancel; may race with concurrent writers.",
                  N);
              R->addRange(Prev->getSourceRange());
              C.emitReport(std::move(R));
              return;
            }
          }
        }
      }
    }
  }

  // Case 2: Assignment statement storing the early read to a local variable.
  // The assignment might be wrapped in other statement nodes; search downwards.
  if (const auto *Assign =
          findSpecificTypeInChildren<BinaryOperator>(Prev)) {
    if (Assign->getOpcode() == BO_Assign) {
      const Expr *LHS = Assign->getLHS()->IgnoreParenCasts();
      const Expr *RHS = Assign->getRHS();
      const auto *LHSRef = dyn_cast<DeclRefExpr>(LHS);
      const VarDecl *VD = LHSRef ? dyn_cast<VarDecl>(LHSRef->getDecl()) : nullptr;
      if (VD && RHS && isUnsafeEarlyReadExpr(RHS, C)) {
        // Ensure that this variable is actually used in RHS conjuncts.
        if (varUsedInConjuncts(Conj, /*StartIdx=*/1, VD)) {
          ExplodedNode *N = C.generateNonFatalErrorNode();
          if (!N)
            return;
          auto R = std::make_unique<PathSensitiveBugReport>(
              *BT,
              "Early read of work->data before checking from_cancel; may race with concurrent writers.",
              N);
          R->addRange(Prev->getSourceRange());
          C.emitReport(std::move(R));
          return;
        }
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects early/speculative read of work->data before checking from_cancel",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
