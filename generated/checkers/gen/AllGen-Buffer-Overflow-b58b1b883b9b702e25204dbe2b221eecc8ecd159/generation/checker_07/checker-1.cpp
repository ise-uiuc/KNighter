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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state:
// - Map "shorten-like" VarDecl* -> iov_iter VarDecl* used to compute it
REGISTER_MAP_WITH_PROGRAMSTATE(ShortenMap, const VarDecl*, const VarDecl*)
// - Set of "shorten-like" VarDecl* that are guarded by a comparison with iter->count
REGISTER_SET_WITH_PROGRAMSTATE(SafeShortenSet, const VarDecl*)

namespace {

static const VarDecl *getVarDeclFromExpr(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD;
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    return getVarDeclFromExpr(UO->getSubExpr());
  }
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    return getVarDeclFromExpr(ME->getBase());
  }
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    return getVarDeclFromExpr(ASE->getBase());
  }
  // Fallback: search downwards for a DeclRefExpr
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD;
  }
  return nullptr;
}

static const VarDecl *extractIterFromIovCountExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  // Find a CallExpr below E which is iov_iter_count(...)
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(E);
  if (!CE)
    return nullptr;

  if (!ExprHasName(CE, "iov_iter_count", C))
    return nullptr;

  if (CE->getNumArgs() < 1)
    return nullptr;

  const Expr *Arg0 = CE->getArg(0);
  return getVarDeclFromExpr(Arg0);
}

static bool isCountMemberExprOfIter(const Expr *E, const VarDecl *&OutIterVD) {
  OutIterVD = nullptr;
  if (!E) return false;
  E = E->IgnoreParenCasts();
  const auto *ME = dyn_cast<MemberExpr>(E);
  if (!ME) return false;

  const ValueDecl *Member = ME->getMemberDecl();
  if (!Member) return false;

  // Check field name is "count"
  if (Member->getName() != "count")
    return false;

  // Extract base variable (iter)
  OutIterVD = getVarDeclFromExpr(ME->getBase());
  return OutIterVD != nullptr;
}

class SAGenTestChecker : public Checker<
    check::PostStmt<DeclStmt>,
    check::Bind,
    check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Size underflow in iov_iter->count", "Integer")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      void recordShortenLike(const VarDecl *ShortenVD, const Expr *RHSorInit, CheckerContext &C) const;
      void maybeReport(const Stmt *S, const VarDecl *IterVD, const VarDecl *ShortenVD, CheckerContext &C) const;
};

void SAGenTestChecker::recordShortenLike(const VarDecl *ShortenVD, const Expr *RHSorInit, CheckerContext &C) const {
  if (!ShortenVD || !RHSorInit)
    return;

  // Ensure the shorten-like variable is of unsigned integer type
  if (!ShortenVD->getType().isUnsignedIntegerType())
    return;

  const Expr *E = RHSorInit->IgnoreParenCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Sub)
    return;

  const Expr *L = BO->getLHS();
  const Expr *R = BO->getRHS();
  if (!L || !R)
    return;

  // Require that left contains iov_iter_count and right contains round_up
  CheckerContext &CRef = const_cast<CheckerContext &>(C);
  if (!ExprHasName(L, "iov_iter_count", CRef))
    return;
  if (!ExprHasName(R, "round_up", CRef))
    return;

  // Extract iter var from the LHS call iov_iter_count(iter)
  const VarDecl *IterVD = extractIterFromIovCountExpr(L, CRef);
  if (!IterVD)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<ShortenMap>(ShortenVD, IterVD);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  // For each declared variable with initializer, check for:
  //   size_t shorten = iov_iter_count(iter) - round_up(...);
  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD || !VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    recordShortenLike(VD, Init, C);
  }
}

void SAGenTestChecker::maybeReport(const Stmt *S, const VarDecl *IterVD, const VarDecl *ShortenVD, CheckerContext &C) const {
  if (!IterVD || !ShortenVD)
    return;

  ProgramStateRef State = C.getState();
  // Is this ShortenVD known and tied to this IterVD?
  const VarDecl *const *MappedIterPtr = State->get<ShortenMap>(ShortenVD);
  if (!MappedIterPtr)
    return;
  const VarDecl *MappedIter = *MappedIterPtr;
  if (!MappedIter || MappedIter != IterVD)
    return;

  // If there is a guard recorded, do not warn.
  if (State->contains<SafeShortenSet>(ShortenVD))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Possible size underflow: round_up(...) may exceed iov_iter_count(); "
      "subtracting it from iter->count can wrap",
      N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));

  // Optionally, erase to avoid duplicate reports along this path
  State = State->remove<ShortenMap>(ShortenVD);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // Case A: Recognize non-declarative assignment for "shorten-like":
  //   shorten = iov_iter_count(iter) - round_up(...);
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      if (const VarDecl *ShortenVD = getVarDeclFromExpr(LHS)) {
        recordShortenLike(ShortenVD, RHS, C);
      }

      // Case C2: iter->count = iter->count - shorten;
      const Expr *AssignLHS = LHS ? LHS->IgnoreParenCasts() : nullptr;
      const Expr *AssignRHS = RHS ? RHS->IgnoreParenCasts() : nullptr;
      const VarDecl *IterInLHS = nullptr;
      if (AssignLHS && AssignRHS && isCountMemberExprOfIter(AssignLHS, IterInLHS)) {
        if (const auto *Sub = dyn_cast<BinaryOperator>(AssignRHS)) {
          if (Sub->getOpcode() == BO_Sub) {
            const Expr *SubLHS = Sub->getLHS();
            const Expr *SubRHS = Sub->getRHS();
            const VarDecl *IterInSubLHS = nullptr;
            if (isCountMemberExprOfIter(SubLHS, IterInSubLHS) && IterInSubLHS == IterInLHS) {
              if (const VarDecl *ShortenVD = getVarDeclFromExpr(SubRHS)) {
                maybeReport(S, IterInLHS, ShortenVD, C);
              }
            }
          }
        }
      }
    }
  }

  // Case C1: Compound subtract:
  //   iter->count -= shorten;
  if (const auto *CAO = dyn_cast<CompoundAssignOperator>(S)) {
    if (CAO->getOpcode() == BO_SubAssign) {
      const Expr *LHS = CAO->getLHS();
      const Expr *RHS = CAO->getRHS();
      const VarDecl *IterVD = nullptr;
      if (isCountMemberExprOfIter(LHS, IterVD)) {
        if (const VarDecl *ShortenVD = getVarDeclFromExpr(RHS)) {
          maybeReport(S, IterVD, ShortenVD, C);
        }
      }
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    return;
  }

  CondE = CondE->IgnoreParenCasts();
  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GE && Op != BO_GT)
    return;

  const Expr *L = BO->getLHS();
  const Expr *R = BO->getRHS();
  if (!L || !R)
    return;

  ProgramStateRef State = C.getState();

  // Pattern 1: shorten >= iter->count  or >
  const VarDecl *ShortenVD = nullptr;
  const VarDecl *IterVD = nullptr;

  // Try L is shorten, R is iter->count
  ShortenVD = getVarDeclFromExpr(L);
  if (ShortenVD && isCountMemberExprOfIter(R, IterVD)) {
    const VarDecl *const *MappedIterPtr = State->get<ShortenMap>(ShortenVD);
    if (MappedIterPtr) {
      const VarDecl *MappedIter = *MappedIterPtr;
      if (MappedIter && MappedIter == IterVD) {
        State = State->add<SafeShortenSet>(ShortenVD);
        C.addTransition(State);
        return;
      }
    }
  }

  // Pattern 2: iter->count >= shorten
  IterVD = nullptr;
  ShortenVD = nullptr;
  if (isCountMemberExprOfIter(L, IterVD)) {
    ShortenVD = getVarDeclFromExpr(R);
    if (ShortenVD) {
      const VarDecl *const *MappedIterPtr = State->get<ShortenMap>(ShortenVD);
      if (MappedIterPtr) {
        const VarDecl *MappedIter = *MappedIterPtr;
        if (MappedIter && MappedIter == IterVD) {
          State = State->add<SafeShortenSet>(ShortenVD);
          C.addTransition(State);
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
      "Detects unsafe subtraction from iter->count using unsigned (iov_iter_count - round_up) without guard",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
