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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/ADT/DenseMap.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Workqueue timeout may cause use-after-free", "Memory Error")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Core helpers
      static bool isWaitForCompletionTimeoutCall(const CallExpr *CE);
      static bool isFreeLikeCallee(const FunctionDecl *FD);
      static bool exprEvaluatesToZero(const Expr *E, ASTContext &AC);
      static const VarDecl* getCtxVarFromCompletionArg(const Expr *Arg);
      static const VarDecl* getDeclRefVar(const Expr *E);

      enum TimeoutBranchKind { TB_Unknown, TB_Then, TB_Else };

      // Condition analysis: classify which branch (then/else) is the "timeout" path
      static TimeoutBranchKind classifyTimeoutBranch(const Expr *Cond,
                                                     const llvm::DenseMap<const VarDecl*, const VarDecl*> &RetToCtx,
                                                     const VarDecl* &OutCtx,
                                                     ASTContext &AC);

      // Mapping collector: ret = wait_for_completion_timeout(&ctx->compl, ...)
      class RetToCtxCollector : public RecursiveASTVisitor<RetToCtxCollector> {
        llvm::DenseMap<const VarDecl*, const VarDecl*> &Map;
        ASTContext &AC;
      public:
        RetToCtxCollector(llvm::DenseMap<const VarDecl*, const VarDecl*> &M, ASTContext &Ctx)
          : Map(M), AC(Ctx) {}

        bool VisitBinaryOperator(BinaryOperator *BO) {
          if (!BO || !BO->isAssignmentOp())
            return true;
          const Expr *RHS = BO->getRHS();
          RHS = RHS ? RHS->IgnoreParenImpCasts() : nullptr;
          const Expr *LHS = BO->getLHS();
          LHS = LHS ? LHS->IgnoreParenImpCasts() : nullptr;

          const auto *CE = RHS ? dyn_cast<CallExpr>(RHS) : nullptr;
          if (!CE || !isWaitForCompletionTimeoutCall(CE))
            return true;

          const VarDecl *RetVD = nullptr;
          if (const auto *DRE = LHS ? dyn_cast<DeclRefExpr>(LHS) : nullptr) {
            RetVD = dyn_cast<VarDecl>(DRE->getDecl());
          }
          if (!RetVD)
            return true;

          if (CE->getNumArgs() >= 1) {
            const VarDecl *CtxVD = getCtxVarFromCompletionArg(CE->getArg(0));
            if (CtxVD) {
              Map[RetVD] = CtxVD;
            }
          }
          return true;
        }

        bool VisitDeclStmt(DeclStmt *DS) {
          if (!DS)
            return true;
          for (auto *DI : DS->decls()) {
            auto *VD = dyn_cast<VarDecl>(DI);
            if (!VD || !VD->hasInit())
              continue;
            const Expr *Init = VD->getInit();
            Init = Init ? Init->IgnoreParenImpCasts() : nullptr;
            const auto *CE = Init ? dyn_cast<CallExpr>(Init) : nullptr;
            if (!CE || !isWaitForCompletionTimeoutCall(CE))
              continue;

            if (CE->getNumArgs() >= 1) {
              const VarDecl *CtxVD = getCtxVarFromCompletionArg(CE->getArg(0));
              if (CtxVD) {
                Map[VD] = CtxVD;
              }
            }
          }
          return true;
        }
      };

      // Branch search: does S contain a free(ctx) call? If yes, return that CallExpr
      static const CallExpr* findFreeOfCtx(const Stmt *S, const VarDecl *CtxVD);
      // Check immediate next statement after an IfStmt within the same CompoundStmt
      static const CallExpr* findUnconditionalFreeAfterIf(const CompoundStmt *ParentCS,
                                                          CompoundStmt::const_body_iterator ItAfterIfEnd,
                                                          const VarDecl *CtxVD);
      // Process a compound statement recursively
      static void processCompoundStmt(const CompoundStmt *CS,
                                      const llvm::DenseMap<const VarDecl*, const VarDecl*> &RetToCtx,
                                      ASTContext &AC, BugReporter &BR, BugType &BT);
};

// ---- Helper implementations ----

static bool calleeNamed(const CallExpr *CE, StringRef Name) {
  if (!CE)
    return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;
  if (const IdentifierInfo *II = FD->getIdentifier())
    return II->getName() == Name;
  return false;
}

bool SAGenTestChecker::isWaitForCompletionTimeoutCall(const CallExpr *CE) {
  return calleeNamed(CE, "wait_for_completion_timeout");
}

bool SAGenTestChecker::isFreeLikeCallee(const FunctionDecl *FD) {
  if (!FD) return false;
  const IdentifierInfo *II = FD->getIdentifier();
  if (!II) return false;
  StringRef N = II->getName();
  return N == "kfree" || N == "kvfree" || N == "vfree";
}

bool SAGenTestChecker::exprEvaluatesToZero(const Expr *E, ASTContext &AC) {
  if (!E) return false;
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, AC)) {
    return R.Val.getInt().isZero();
  }
  return false;
}

const VarDecl* SAGenTestChecker::getDeclRefVar(const Expr *E) {
  if (!E) return nullptr;
  // Try direct DeclRefExpr first
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
    return dyn_cast<VarDecl>(DRE->getDecl());
  }
  // Fallback: search in children
  if (const auto *DRE2 = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    return dyn_cast<VarDecl>(DRE2->getDecl());
  }
  return nullptr;
}

const VarDecl* SAGenTestChecker::getCtxVarFromCompletionArg(const Expr *Arg) {
  if (!Arg) return nullptr;
  // Typical form: &ctx->compl or &reset_data.compl
  // Find the DeclRefExpr in children, which should refer to the base variable 'ctx'/'reset_data'.
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(Arg)) {
    return dyn_cast<VarDecl>(DRE->getDecl());
  }
  return nullptr;
}

SAGenTestChecker::TimeoutBranchKind
SAGenTestChecker::classifyTimeoutBranch(const Expr *Cond,
                                        const llvm::DenseMap<const VarDecl*, const VarDecl*> &RetToCtx,
                                        const VarDecl* &OutCtx,
                                        ASTContext &AC) {
  OutCtx = nullptr;
  if (!Cond) return TB_Unknown;

  const Expr *E = Cond->IgnoreParenImpCasts();

  // Case 1: if (wait_for_completion_timeout(...))
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    if (isWaitForCompletionTimeoutCall(CE)) {
      if (CE->getNumArgs() >= 1) {
        OutCtx = getCtxVarFromCompletionArg(CE->getArg(0));
      }
      // Non-zero => success, zero => timeout
      return OutCtx ? TB_Else : TB_Unknown;
    }
  }

  // Case 2: if (! <expr>)
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *CE = dyn_cast<CallExpr>(Sub)) {
        if (isWaitForCompletionTimeoutCall(CE)) {
          if (CE->getNumArgs() >= 1) {
            OutCtx = getCtxVarFromCompletionArg(CE->getArg(0));
          }
          return OutCtx ? TB_Then : TB_Unknown;
        }
      } else if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        const VarDecl *RetVD = dyn_cast<VarDecl>(DRE->getDecl());
        if (RetVD) {
          auto It = RetToCtx.find(RetVD);
          if (It != RetToCtx.end()) {
            OutCtx = It->second;
            return TB_Then; // !ret => timeout
          }
        }
      }
    }
  }

  // Case 3: Binary comparisons with zero
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

    auto isZero = [&](const Expr *X){ return exprEvaluatesToZero(X, AC); };

    // LHS is call or ret var, RHS is zero
    if (isZero(R)) {
      // LHS can be call or DeclRef
      if (const auto *CE = dyn_cast<CallExpr>(L)) {
        if (isWaitForCompletionTimeoutCall(CE)) {
          if (CE->getNumArgs() >= 1) {
            OutCtx = getCtxVarFromCompletionArg(CE->getArg(0));
          }
          if (!OutCtx) return TB_Unknown;
          if (BO->getOpcode() == BO_EQ)
            return TB_Then; // call == 0 => timeout in then
          if (BO->getOpcode() == BO_NE)
            return TB_Else; // call != 0 => timeout in else (success in then)
        }
      } else if (const auto *DRE = dyn_cast<DeclRefExpr>(L)) {
        const VarDecl *RetVD = dyn_cast<VarDecl>(DRE->getDecl());
        if (RetVD) {
          auto It = RetToCtx.find(RetVD);
          if (It != RetToCtx.end()) {
            OutCtx = It->second;
            if (BO->getOpcode() == BO_EQ)
              return TB_Then; // ret == 0 => timeout
            if (BO->getOpcode() == BO_NE)
              return TB_Else; // ret != 0 => success
          }
        }
      }
    }

    // RHS is call/ret, LHS is zero
    if (isZero(L)) {
      if (const auto *CE = dyn_cast<CallExpr>(R)) {
        if (isWaitForCompletionTimeoutCall(CE)) {
          if (CE->getNumArgs() >= 1) {
            OutCtx = getCtxVarFromCompletionArg(CE->getArg(0));
          }
          if (!OutCtx) return TB_Unknown;
          if (BO->getOpcode() == BO_EQ)
            return TB_Then; // 0 == call => timeout
          if (BO->getOpcode() == BO_NE)
            return TB_Else; // 0 != call => success
        }
      } else if (const auto *DRE = dyn_cast<DeclRefExpr>(R)) {
        const VarDecl *RetVD = dyn_cast<VarDecl>(DRE->getDecl());
        if (RetVD) {
          auto It = RetToCtx.find(RetVD);
          if (It != RetToCtx.end()) {
            OutCtx = It->second;
            if (BO->getOpcode() == BO_EQ)
              return TB_Then; // 0 == ret => timeout
            if (BO->getOpcode() == BO_NE)
              return TB_Else; // 0 != ret => success
          }
        }
      }
    }
  }

  // Case 4: if (ret)
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const VarDecl *RetVD = dyn_cast<VarDecl>(DRE->getDecl());
    if (RetVD) {
      auto It = RetToCtx.find(RetVD);
      if (It != RetToCtx.end()) {
        OutCtx = It->second;
        return TB_Else; // ret != 0 => success, else => timeout
      }
    }
  }

  return TB_Unknown;
}

const CallExpr* SAGenTestChecker::findFreeOfCtx(const Stmt *S, const VarDecl *CtxVD) {
  if (!S || !CtxVD) return nullptr;

  class Finder : public RecursiveASTVisitor<Finder> {
    const VarDecl *Target;
    const CallExpr *Found = nullptr;
  public:
    Finder(const VarDecl *VD) : Target(VD) {}
    bool VisitCallExpr(CallExpr *CE) {
      if (Found || !CE) return true;
      const FunctionDecl *FD = CE->getDirectCallee();
      if (!FD || !isFreeLikeCallee(FD))
        return true;
      if (CE->getNumArgs() < 1)
        return true;
      const VarDecl *ArgVD = getDeclRefVar(CE->getArg(0));
      if (ArgVD && ArgVD == Target) {
        Found = CE;
        // We can stop traversal here by returning false, but we need to keep the API consistent.
        // Returning true is also fine; we will just ignore further matches.
      }
      return true;
    }
    const CallExpr* get() const { return Found; }
  };

  Finder F(CtxVD);
  F.TraverseStmt(const_cast<Stmt*>(S));
  return F.get();
}

const CallExpr* SAGenTestChecker::findUnconditionalFreeAfterIf(const CompoundStmt *ParentCS,
                                                               CompoundStmt::const_body_iterator ItAfterIfEnd,
                                                               const VarDecl *CtxVD) {
  if (!ParentCS || !CtxVD) return nullptr;
  // Look only at the immediate next statements until a ReturnStmt or another IfStmt.
  for (auto It = ItAfterIfEnd; It != ParentCS->body_end(); ++It) {
    const Stmt *S = *It;
    if (!S) continue;
    if (isa<ReturnStmt>(S) || isa<IfStmt>(S))
      break;

    // Only consider a direct call as being unconditional
    if (const auto *CE = dyn_cast<CallExpr>(S)) {
      const FunctionDecl *FD = CE->getDirectCallee();
      if (!FD) continue;
      if (!isFreeLikeCallee(FD)) continue;

      if (CE->getNumArgs() >= 1) {
        const VarDecl *ArgVD = getDeclRefVar(CE->getArg(0));
        if (ArgVD && ArgVD == CtxVD) {
          return CE;
        }
      }
    }
    // If we hit any other kind of statement, we continue to see if the next one is a direct free.
    // Stop if statement list grows long to avoid noise; but keeping it simple for now.
  }
  return nullptr;
}

void SAGenTestChecker::processCompoundStmt(const CompoundStmt *CS,
                                           const llvm::DenseMap<const VarDecl*, const VarDecl*> &RetToCtx,
                                           ASTContext &AC, BugReporter &BR, BugType &BT) {
  if (!CS) return;

  // Iterate with index/iterators to be able to inspect the next statement.
  for (auto It = CS->body_begin(), E = CS->body_end(); It != E; ++It) {
    const Stmt *S = *It;

    // Recurse into nested CompoundStmts to find inner patterns as well.
    if (const auto *InnerCS = dyn_cast<CompoundStmt>(S)) {
      processCompoundStmt(InnerCS, RetToCtx, AC, BR, BT);
    }

    const auto *IfS = dyn_cast<IfStmt>(S);
    if (!IfS)
      continue;

    const Expr *Cond = IfS->getCond();
    const VarDecl *CtxVD = nullptr;
    TimeoutBranchKind TB = classifyTimeoutBranch(Cond, RetToCtx, CtxVD, AC);
    if (TB == TB_Unknown || !CtxVD)
      continue;

    // Identify the timeout branch
    const Stmt *TimeoutBranch = (TB == TB_Then) ? IfS->getThen() : IfS->getElse();

    // 1) Definite bug: free(ctx) in the timeout branch
    if (TimeoutBranch) {
      if (const CallExpr *FreeCE = findFreeOfCtx(TimeoutBranch, CtxVD)) {
        PathDiagnosticLocation Loc(FreeCE->getExprLoc(), BR.getSourceManager());
        auto R = std::make_unique<BasicBugReport>(
            BT,
            "Freeing work context on timeout after wait_for_completion_timeout; worker may still use it (use-after-free).",
            Loc);
        R->addRange(FreeCE->getSourceRange());
        BR.emitReport(std::move(R));
      }
    }

    // 2) Suspicious bug: unconditional free(ctx) right after the if-statement
    auto NextIt = It;
    ++NextIt;
    if (const CallExpr *FreeCE = findUnconditionalFreeAfterIf(CS, NextIt, CtxVD)) {
      PathDiagnosticLocation Loc(FreeCE->getExprLoc(), BR.getSourceManager());
      auto R = std::make_unique<BasicBugReport>(
          BT,
          "Freeing work context unconditionally after wait_for_completion_timeout; may free on timeout while worker still uses it.",
          Loc);
      R->addRange(FreeCE->getSourceRange());
      BR.emitReport(std::move(R));
    }

    // Recurse into then/else branches to detect nested constructs
    if (const auto *ThenCS = dyn_cast_or_null<CompoundStmt>(IfS->getThen()))
      processCompoundStmt(ThenCS, RetToCtx, AC, BR, BT);
    if (const auto *ElseCS = dyn_cast_or_null<CompoundStmt>(IfS->getElse()))
      processCompoundStmt(ElseCS, RetToCtx, AC, BR, BT);
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &AC = Mgr.getASTContext();

  // Build ret -> ctx mapping for the entire function body
  llvm::DenseMap<const VarDecl*, const VarDecl*> RetToCtx;
  RetToCtxCollector Collector(RetToCtx, AC);
  Collector.TraverseStmt(const_cast<Stmt*>(Body));

  const auto *CS = dyn_cast<CompoundStmt>(Body);
  if (!CS)
    return;

  processCompoundStmt(CS, RetToCtx, AC, BR, *BT);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing a work context on wait_for_completion_timeout timeout path leading to possible UAF",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
