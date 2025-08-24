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
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/AST/ParentMapContext.h"
#include <vector>
#include <utility>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Leak on early exit before register_netdev", "Memory Management")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Helpers
      static bool isCalleeNamed(const CallExpr *CE, std::initializer_list<const char*> Names);
      static bool isNetdevAllocCall(const CallExpr *CE);
      static bool isRegisterNetdevForVar(const CallExpr *CE, const VarDecl *VD);
      static bool isFreeNetdevForVar(const CallExpr *CE, const VarDecl *VD);

      static const VarDecl* getAssignedVarFromCall(const CallExpr *CE, ASTContext &Ctx);
      static bool stmtContains(const Stmt *Parent, const Stmt *Child);
      static void collectCallsAndExits(const Stmt *S,
                                       std::vector<const CallExpr*> &Calls,
                                       std::vector<const Stmt*> &Exits);

      static bool isBetween(const SourceManager &SM,
                            SourceLocation StartAfter,
                            const Stmt *Mid,
                            SourceLocation EndBefore);

      static const Stmt* findNearestParentOfKind(const Stmt *S, ASTContext &Ctx, std::function<bool(const Stmt*)> Pred);
      static const CompoundStmt* findNearestEnclosingCompound(const Stmt *S, ASTContext &Ctx);

      static bool isNullTestOfVar(const Expr *Cond, const VarDecl *VD, ASTContext &Ctx);
      static bool isExitGuardedByNullOfVar(const Stmt *Exit, const VarDecl *VD, ASTContext &Ctx);

      static bool containsFreeNetdevForVarAfterStart(const Stmt *S, const VarDecl *VD,
                                                     const SourceManager &SM, SourceLocation StartAfter);

      void analyzeLoopBody(const Stmt *LoopBody, const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

static SourceLocation getBeginTokenLoc(const Stmt *S, const SourceManager &SM) {
  return SM.getExpansionLoc(S->getBeginLoc());
}
static SourceLocation getEndTokenLoc(const Stmt *S, const SourceManager &SM) {
  return SM.getExpansionLoc(S->getEndLoc());
}

bool SAGenTestChecker::isCalleeNamed(const CallExpr *CE, std::initializer_list<const char*> Names) {
  if (!CE) return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD) return false;
  StringRef Name = FD->getName();
  for (const char *N : Names) {
    if (Name.equals(N))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isNetdevAllocCall(const CallExpr *CE) {
  return isCalleeNamed(CE, {"alloc_etherdev", "alloc_netdev", "alloc_netdev_mqs"});
}

static const DeclRefExpr* getAsDeclRef(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  return dyn_cast<DeclRefExpr>(E);
}

bool SAGenTestChecker::isRegisterNetdevForVar(const CallExpr *CE, const VarDecl *VD) {
  if (!CE || !VD) return false;
  if (!isCalleeNamed(CE, {"register_netdev"})) return false;
  if (CE->getNumArgs() != 1) return false;
  const Expr *Arg = CE->getArg(0);
  if (const DeclRefExpr *DRE = getAsDeclRef(Arg)) {
    if (const VarDecl *A = dyn_cast<VarDecl>(DRE->getDecl()))
      return A == VD;
  }
  return false;
}

bool SAGenTestChecker::isFreeNetdevForVar(const CallExpr *CE, const VarDecl *VD) {
  if (!CE || !VD) return false;
  if (!isCalleeNamed(CE, {"free_netdev"})) return false;
  if (CE->getNumArgs() != 1) return false;
  const Expr *Arg = CE->getArg(0);
  if (const DeclRefExpr *DRE = getAsDeclRef(Arg)) {
    if (const VarDecl *A = dyn_cast<VarDecl>(DRE->getDecl()))
      return A == VD;
  }
  return false;
}

bool SAGenTestChecker::stmtContains(const Stmt *Parent, const Stmt *Child) {
  if (!Parent || !Child) return false;
  if (Parent == Child) return true;
  for (const Stmt *Sub : Parent->children()) {
    if (Sub && stmtContains(Sub, Child))
      return true;
  }
  return false;
}

const VarDecl* SAGenTestChecker::getAssignedVarFromCall(const CallExpr *CE, ASTContext &Ctx) {
  if (!CE) return nullptr;

  DynTypedNode Node = DynTypedNode::create(*CE);

  // Climb up through wrappers to find either a BinaryOperator (=) or a DeclStmt.
  for (int depth = 0; depth < 16; ++depth) {
    auto Parents = Ctx.getParents(Node);
    if (Parents.empty())
      break;

    // Try to find a BinaryOperator parent (assignment) first.
    const BinaryOperator *FoundBO = nullptr;
    const DeclStmt *FoundDS = nullptr;
    const Expr *FoundExpr = nullptr;

    for (const auto &P : Parents) {
      if (!FoundBO) FoundBO = P.get<BinaryOperator>();
      if (!FoundDS) FoundDS = P.get<DeclStmt>();
      if (!FoundExpr) FoundExpr = P.get<Expr>();
    }

    if (FoundBO) {
      const BinaryOperator *BO = FoundBO;
      if (BO->isAssignmentOp() && BO->getOpcode() == BO_Assign) {
        if (stmtContains(BO->getRHS(), CE)) {
          const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
          if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
            if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl()))
              return VD;
          }
        }
      }
      // If it's some other binop or not containing CE, continue climbing.
      Node = DynTypedNode::create(*BO);
      continue;
    }

    if (FoundDS) {
      const DeclStmt *DS = FoundDS;
      if (DS->isSingleDecl()) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
          if (const Expr *Init = VD->getInit()) {
            if (stmtContains(Init, CE))
              return VD;
          }
        }
      }
      Node = DynTypedNode::create(*DS);
      continue;
    }

    if (FoundExpr) {
      Node = DynTypedNode::create(*FoundExpr);
      continue;
    }

    break;
  }

  return nullptr;
}

void SAGenTestChecker::collectCallsAndExits(const Stmt *S,
                                            std::vector<const CallExpr*> &Calls,
                                            std::vector<const Stmt*> &Exits) {
  if (!S) return;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    Calls.push_back(CE);
  } else if (isa<GotoStmt>(S) || isa<ReturnStmt>(S)) {
    Exits.push_back(S);
  }

  for (const Stmt *Child : S->children()) {
    if (Child)
      collectCallsAndExits(Child, Calls, Exits);
  }
}

bool SAGenTestChecker::isBetween(const SourceManager &SM,
                                 SourceLocation StartAfter,
                                 const Stmt *Mid,
                                 SourceLocation EndBefore) {
  if (!Mid.isNotNull()) return false;
  SourceLocation MidBegin = getBeginTokenLoc(Mid, SM);
  SourceLocation MidEnd   = getEndTokenLoc(Mid, SM);

  bool AfterStart = SM.isBeforeInTranslationUnit(StartAfter, MidBegin);
  bool BeforeEnd  = SM.isBeforeInTranslationUnit(MidEnd, EndBefore);
  return AfterStart && BeforeEnd;
}

const Stmt* SAGenTestChecker::findNearestParentOfKind(const Stmt *S, ASTContext &Ctx, std::function<bool(const Stmt*)> Pred) {
  if (!S) return nullptr;
  DynTypedNode Node = DynTypedNode::create(*S);
  for (int depth = 0; depth < 32; ++depth) {
    auto Parents = Ctx.getParents(Node);
    if (Parents.empty())
      break;
    const Stmt *Found = nullptr;
    const Stmt *AnyParent = nullptr;
    for (const auto &P : Parents) {
      if (const Stmt *PS = P.get<Stmt>()) {
        AnyParent = PS;
        if (Pred(PS)) {
          Found = PS;
          break;
        }
      }
    }
    if (Found)
      return Found;
    if (!AnyParent)
      break;
    Node = DynTypedNode::create(*AnyParent);
  }
  return nullptr;
}

const CompoundStmt* SAGenTestChecker::findNearestEnclosingCompound(const Stmt *S, ASTContext &Ctx) {
  return dyn_cast_or_null<CompoundStmt>(findNearestParentOfKind(
      S, Ctx, [](const Stmt *X) { return isa<CompoundStmt>(X); }));
}

static bool isZeroOrNullPtr(const Expr *E, ASTContext &Ctx) {
  if (!E) return false;
  return E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
}

bool SAGenTestChecker::isNullTestOfVar(const Expr *Cond, const VarDecl *VD, ASTContext &Ctx) {
  if (!Cond || !VD) return false;
  const Expr *C = Cond->IgnoreParenImpCasts();

  // if (!vd)
  if (const auto *UO = dyn_cast<UnaryOperator>(C)) {
    if (UO->getOpcode() == UO_LNot) {
      if (const DeclRefExpr *DRE = getAsDeclRef(UO->getSubExpr())) {
        if (const VarDecl *V = dyn_cast<VarDecl>(DRE->getDecl()))
          return V == VD;
      }
    }
  }

  // if (vd == NULL) or if (vd != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(C)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      const DeclRefExpr *LDRE = dyn_cast<DeclRefExpr>(LHS);
      const DeclRefExpr *RDRE = dyn_cast<DeclRefExpr>(RHS);

      if (LDRE && dyn_cast<VarDecl>(LDRE->getDecl()) == VD && isZeroOrNullPtr(RHS, Ctx))
        return true;
      if (RDRE && dyn_cast<VarDecl>(RDRE->getDecl()) == VD && isZeroOrNullPtr(LHS, Ctx))
        return true;
    }
  }

  // if (vd) -- positive test
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(C)) {
    if (const VarDecl *V = dyn_cast<VarDecl>(DRE->getDecl()))
      return V == VD;
  }

  return false;
}

bool SAGenTestChecker::isExitGuardedByNullOfVar(const Stmt *Exit, const VarDecl *VD, ASTContext &Ctx) {
  if (!Exit || !VD) return false;
  const IfStmt *IS = dyn_cast_or_null<IfStmt>(findNearestParentOfKind(
      Exit, Ctx, [](const Stmt *X) { return isa<IfStmt>(X); }));
  if (!IS) return false;

  const Expr *Cond = IS->getCond();
  if (!Cond) return false;

  // We conservatively assume that if the nearest enclosing if-statement's
  // condition is a null/non-null test of VD, then the exit is guarded by a
  // null-check of the var, and thus no leak occurs when VD is NULL.
  return isNullTestOfVar(Cond, VD, Ctx);
}

bool SAGenTestChecker::containsFreeNetdevForVarAfterStart(const Stmt *S, const VarDecl *VD,
                                                          const SourceManager &SM, SourceLocation StartAfter) {
  if (!S || !VD) return false;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (isFreeNetdevForVar(CE, VD)) {
      if (SM.isBeforeInTranslationUnit(StartAfter, getBeginTokenLoc(CE, SM)))
        return true;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (Child && containsFreeNetdevForVarAfterStart(Child, VD, SM, StartAfter))
      return true;
  }
  return false;
}

void SAGenTestChecker::analyzeLoopBody(const Stmt *LoopBody, const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!LoopBody) return;

  ASTContext &Ctx = Mgr.getASTContext();
  const SourceManager &SM = BR.getSourceManager();
  AnalysisDeclContext *AC = Mgr.getAnalysisDeclContext(D);

  // Collect all calls and exits within the loop body.
  std::vector<const CallExpr*> Calls;
  std::vector<const Stmt*> Exits;
  collectCallsAndExits(LoopBody, Calls, Exits);

  // For each allocation inside the loop, analyze early exits before register_netdev.
  for (const CallExpr *AllocCE : Calls) {
    if (!isNetdevAllocCall(AllocCE))
      continue;

    const VarDecl *VD = getAssignedVarFromCall(AllocCE, Ctx);
    if (!VD)
      continue; // Only handle obvious assignment targets.

    // Find the first register_netdev(VD) after the allocation.
    const CallExpr *FirstReg = nullptr;
    SourceLocation AllocEnd = getEndTokenLoc(AllocCE, SM);
    SourceLocation BodyEnd = getEndTokenLoc(LoopBody, SM);
    SourceLocation EndBoundLoc = BodyEnd;

    for (const CallExpr *C : Calls) {
      if (isRegisterNetdevForVar(C, VD)) {
        if (SM.isBeforeInTranslationUnit(AllocEnd, getBeginTokenLoc(C, SM))) {
          if (!FirstReg ||
              SM.isBeforeInTranslationUnit(getBeginTokenLoc(C, SM),
                                           getBeginTokenLoc(FirstReg, SM))) {
            FirstReg = C;
          }
        }
      }
    }
    if (FirstReg)
      EndBoundLoc = getBeginTokenLoc(FirstReg, SM);

    // Look for exits between allocation and registration.
    for (const Stmt *ExitS : Exits) {
      if (!isBetween(SM, AllocEnd, ExitS, EndBoundLoc))
        continue;

      // Skip exits that are guarded by a null-check on VD (allocation failed path).
      if (isExitGuardedByNullOfVar(ExitS, VD, Ctx))
        continue;

      // Ensure there is a free_netdev(VD) before this exit in the same enclosing compound.
      const CompoundStmt *CS = findNearestEnclosingCompound(ExitS, Ctx);
      bool HasLocalFree = false;
      if (CS) {
        for (const Stmt *Child : CS->body()) {
          if (Child == ExitS)
            break;
          // Consider only those after the allocation point.
          if (SM.isBeforeInTranslationUnit(AllocEnd, getBeginTokenLoc(Child, SM))) {
            if (containsFreeNetdevForVarAfterStart(Child, VD, SM, AllocEnd)) {
              HasLocalFree = true;
              break;
            }
          }
        }
      }

      if (!HasLocalFree) {
        // Report: missing free_netdev before early exit.
        PathDiagnosticLocation ELoc =
            PathDiagnosticLocation::createBegin(ExitS, SM, AC);
        auto R = std::make_unique<BasicBugReport>(
            *BT,
            "net_device allocated in loop may leak on early exit; "
            "missing free_netdev before goto/return",
            ELoc);
        R->addRange(ExitS->getSourceRange());
        BR.emitReport(std::move(R));
      }
    }
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // Recursively scan for loops and analyze each.
  std::vector<const Stmt*> Worklist;
  Worklist.push_back(Body);

  while (!Worklist.empty()) {
    const Stmt *S = Worklist.back();
    Worklist.pop_back();

    if (!S) continue;

    if (const auto *FS = dyn_cast<ForStmt>(S)) {
      analyzeLoopBody(FS->getBody(), D, Mgr, BR);
    } else if (const auto *WS = dyn_cast<WhileStmt>(S)) {
      analyzeLoopBody(WS->getBody(), D, Mgr, BR);
    } else if (const auto *DS = dyn_cast<DoStmt>(S)) {
      analyzeLoopBody(DS->getBody(), D, Mgr, BR);
    }

    for (const Stmt *Child : S->children()) {
      if (Child)
        Worklist.push_back(Child);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects net_device leak on early goto/return between alloc_etherdev and register_netdev in loops",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
