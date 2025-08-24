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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track the "shorten" variable and which iov_iter variable it is derived from.
REGISTER_MAP_WITH_PROGRAMSTATE(ShortenIterMap, const VarDecl*, const VarDecl*)
// Track whether a given "shorten" variable is guarded (bounded) before use.
REGISTER_MAP_WITH_PROGRAMSTATE(ShortenGuardedMap, const VarDecl*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>,
                                        check::Bind,
                                        check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded iov_iter count decrement", "Arithmetic")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:

      // Helpers
      static bool isUnsignedSizeLike(QualType T);
      static const VarDecl* getVarDeclFromDeclRefExpr(const Expr *E);
      static const VarDecl* getIterVarFromCountExpr(const Expr *E, CheckerContext &C);
      static const VarDecl* getIterVarFromIterCountCall(const CallExpr *CE, CheckerContext &C);
      static const VarDecl* getIterVarFromMemberCount(const Expr *E);
      static bool isIterCountMemberExprForVar(const Expr *E, const VarDecl *IterVD);

      static bool isSubOfIterCount(const Expr *E, const VarDecl* &OutIter, CheckerContext &C);

      static const BinaryOperator* getAsBinaryOperator(const Stmt *S);
      static const CompoundAssignOperator* getAsCompoundAssignOperator(const Stmt *S);

      void recordShortenVar(const VarDecl *ShortenVD, const VarDecl *IterVD, CheckerContext &C) const;

      const VarDecl* findShortenVarInExprForIter(const Expr *E, CheckerContext &C, ProgramStateRef State, const VarDecl *IterVD) const;

      void maybeReportOnSubtract(const Stmt *S, const VarDecl *IterVD, const VarDecl *ShortenVD, CheckerContext &C) const;
};

bool SAGenTestChecker::isUnsignedSizeLike(QualType T) {
  if (T.isNull())
    return false;
  return T->isUnsignedIntegerType();
}

const VarDecl* SAGenTestChecker::getVarDeclFromDeclRefExpr(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD;
  }
  return nullptr;
}

// Try to get the iov_iter VarDecl from an expression which is either:
// - iov_iter_count(iter)
// - iter->count (or iter.count)
const VarDecl* SAGenTestChecker::getIterVarFromCountExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();

  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    return getIterVarFromIterCountCall(CE, C);
  }

  if (const VarDecl *VD = getIterVarFromMemberCount(E))
    return VD;

  return nullptr;
}

const VarDecl* SAGenTestChecker::getIterVarFromIterCountCall(const CallExpr *CE, CheckerContext &C) {
  if (!CE) return nullptr;
  // Prefer textual name check for robustness (macros/inline).
  if (!ExprHasName(CE, "iov_iter_count", C))
    return nullptr;
  if (CE->getNumArgs() < 1)
    return nullptr;
  const Expr *Arg0 = CE->getArg(0)->IgnoreParenImpCasts();
  return getVarDeclFromDeclRefExpr(Arg0);
}

const VarDecl* SAGenTestChecker::getIterVarFromMemberCount(const Expr *E) {
  E = E ? E->IgnoreParenImpCasts() : nullptr;
  if (!E) return nullptr;
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    // We expect member named "count".
    if (ME->getMemberNameInfo().getAsString() != "count")
      return nullptr;
    const Expr *Base = ME->getBase();
    if (!Base) return nullptr;
    Base = Base->IgnoreParenImpCasts();
    return getVarDeclFromDeclRefExpr(Base);
  }
  return nullptr;
}

bool SAGenTestChecker::isIterCountMemberExprForVar(const Expr *E, const VarDecl *IterVD) {
  if (!E || !IterVD) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (ME->getMemberNameInfo().getAsString() != "count")
      return false;
    const VarDecl *BaseVD = getVarDeclFromDeclRefExpr(ME->getBase());
    return BaseVD == IterVD;
  }
  return false;
}

// Check if E is a subtraction where LHS is iov_iter_count(iter) or iter->count.
// If yes, set OutIter to that iter VarDecl.
bool SAGenTestChecker::isSubOfIterCount(const Expr *E, const VarDecl* &OutIter, CheckerContext &C) {
  OutIter = nullptr;
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Sub)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();

  if (const VarDecl *VD = getIterVarFromCountExpr(LHS, C)) {
    OutIter = VD;
    return true;
  }
  return false;
}

const BinaryOperator* SAGenTestChecker::getAsBinaryOperator(const Stmt *S) {
  return dyn_cast_or_null<BinaryOperator>(S);
}
const CompoundAssignOperator* SAGenTestChecker::getAsCompoundAssignOperator(const Stmt *S) {
  return dyn_cast_or_null<CompoundAssignOperator>(S);
}

void SAGenTestChecker::recordShortenVar(const VarDecl *ShortenVD, const VarDecl *IterVD, CheckerContext &C) const {
  if (!ShortenVD || !IterVD)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<ShortenIterMap>(ShortenVD, IterVD);
  State = State->set<ShortenGuardedMap>(ShortenVD, false);
  C.addTransition(State);
}

// Find a VarDecl (shorten var) referenced in E that is already recorded and maps to IterVD.
const VarDecl* SAGenTestChecker::findShortenVarInExprForIter(const Expr *E, CheckerContext &C, ProgramStateRef State, const VarDecl *IterVD) const {
  if (!E || !IterVD) return nullptr;
  // Try to find a DeclRefExpr in children and check if it is a known shorten var for this iter.
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (const VarDecl *const *MappedIter = State->get<ShortenIterMap>(VD)) {
        if (*MappedIter == IterVD)
          return VD;
      }
    }
  }
  return nullptr;
}

void SAGenTestChecker::maybeReportOnSubtract(const Stmt *S, const VarDecl *IterVD, const VarDecl *ShortenVD, CheckerContext &C) const {
  if (!S || !IterVD || !ShortenVD) return;

  ProgramStateRef State = C.getState();
  const bool *Guarded = State->get<ShortenGuardedMap>(ShortenVD);
  // Only report if we know this shorten is tracked and not guarded.
  if (!Guarded || *Guarded == true)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unbounded iov_iter count decrement may underflow",
      N);
  R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// Record "shorten" variables created via declarations with initializers like
//   size_t shorten = iov_iter_count(iter) - something;
//   size_t shorten = iter->count - something;
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS) return;

  for (const auto *DI : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(DI);
    if (!VD) continue;

    if (!VD->hasInit())
      continue;

    if (!isUnsignedSizeLike(VD->getType()))
      continue;

    const Expr *Init = VD->getInit();
    if (!Init) continue;

    const VarDecl *IterVD = nullptr;
    if (isSubOfIterCount(Init, IterVD, C)) {
      recordShortenVar(VD, IterVD, C);
      continue;
    }

    // Also allow "iter->count - something"
    const Expr *InitE = Init->IgnoreParenImpCasts();
    if (const auto *BO = dyn_cast<BinaryOperator>(InitE)) {
      if (BO->getOpcode() == BO_Sub) {
        const VarDecl *BaseIter = getIterVarFromMemberCount(BO->getLHS());
        if (BaseIter) {
          recordShortenVar(VD, BaseIter, C);
        }
      }
    }
  }
}

// Detect:
// 1) Recording assignment form: shorten = iov_iter_count(iter) - ...;
// 2) Unsafe decrement:
//    - iter->count -= shorten;
//    - iter->count = iter->count - shorten;
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S) return;

  ProgramStateRef State = C.getState();

  // Part A: Record shorten when assigned outside of declaration.
  if (const auto *BO = getAsBinaryOperator(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const VarDecl *LHSVD = getVarDeclFromDeclRefExpr(BO->getLHS());
      if (LHSVD && isUnsignedSizeLike(LHSVD->getType())) {
        const VarDecl *IterVD = nullptr;
        if (isSubOfIterCount(BO->getRHS(), IterVD, C)) {
          recordShortenVar(LHSVD, IterVD, C);
        } else {
          // Also allow "iter->count - something"
          const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
          if (const auto *SubBO = dyn_cast<BinaryOperator>(RHS)) {
            if (SubBO->getOpcode() == BO_Sub) {
              const VarDecl *BaseIter = getIterVarFromMemberCount(SubBO->getLHS());
              if (BaseIter) {
                recordShortenVar(LHSVD, BaseIter, C);
              }
            }
          }
        }
      }
    }
  }

  // Part B: Find unsafe decrement of iter->count by shorten.
  // Case 1: iter->count -= shorten;
  if (const auto *CAO = getAsCompoundAssignOperator(S)) {
    if (CAO->getOpcode() == BO_SubAssign) {
      const Expr *LHS = CAO->getLHS()->IgnoreParenImpCasts();
      const VarDecl *IterVD = getIterVarFromMemberCount(LHS);
      if (IterVD) {
        const VarDecl *ShortenVD = findShortenVarInExprForIter(CAO->getRHS(), C, State, IterVD);
        if (ShortenVD) {
          maybeReportOnSubtract(S, IterVD, ShortenVD, C);
        }
      }
    }
  }

  // Case 2: iter->count = iter->count - shorten;
  if (const auto *BO2 = getAsBinaryOperator(S)) {
    if (BO2->getOpcode() == BO_Assign) {
      const Expr *LHS = BO2->getLHS()->IgnoreParenImpCasts();
      const VarDecl *IterVD = getIterVarFromMemberCount(LHS);
      if (IterVD) {
        const Expr *RHS = BO2->getRHS()->IgnoreParenImpCasts();
        if (const auto *SubBO = dyn_cast<BinaryOperator>(RHS)) {
          if (SubBO->getOpcode() == BO_Sub) {
            // Ensure RHS LHS is same iter->count
            if (isIterCountMemberExprForVar(SubBO->getLHS(), IterVD)) {
              const VarDecl *ShortenVD = findShortenVarInExprForIter(SubBO->getRHS(), C, State, IterVD);
              if (ShortenVD) {
                maybeReportOnSubtract(S, IterVD, ShortenVD, C);
              }
            }
          }
        }
      }
    }
  }
}

// Mark "shorten" as guarded if we see a condition like:
//   if (shorten >= iter->count) ...    or    if (shorten > iter->count)
// Symmetric forms are also accepted.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition) {
    C.addTransition(C.getState());
    return;
  }

  const auto *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(C.getState());
    return;
  }

  CondE = CondE->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO) {
    C.addTransition(C.getState());
    return;
  }

  BinaryOperatorKind Op = BO->getOpcode();
  if (Op != BO_GE && Op != BO_GT && Op != BO_LE && Op != BO_LT)
  {
    C.addTransition(C.getState());
    return;
  }

  ProgramStateRef State = C.getState();
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  // Helper lambda to process a pattern: ShortenVD (DeclRefExpr) vs iter->count (MemberExpr)
  auto TryMarkGuarded = [&](const Expr *ShortenExpr, const Expr *IterCountExpr) -> bool {
    const VarDecl *ShortenVD = getVarDeclFromDeclRefExpr(ShortenExpr);
    if (!ShortenVD) return false;

    const VarDecl *const *MappedIterPtr = State->get<ShortenIterMap>(ShortenVD);
    if (!MappedIterPtr) return false;
    const VarDecl *MappedIter = *MappedIterPtr;

    if (!isIterCountMemberExprForVar(IterCountExpr, MappedIter))
      return false;

    // Mark guarded
    State = State->set<ShortenGuardedMap>(ShortenVD, true);
    C.addTransition(State);
    return true;
  };

  // Accept both sides
  if (TryMarkGuarded(LHS, RHS))
    return;
  (void)TryMarkGuarded(RHS, LHS);

  // If no match, still transition
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect unbounded iov_iter count decrement that may underflow (size_t)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
