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
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringRef.h"
#include <string>
#include <unordered_map>
#include <vector>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody, check::EndAnalysis> {
   mutable std::unique_ptr<BugType> BT;

   // Data collected across functions (per translation unit)
   struct WorkerInfo {
     std::string RecordName;
     std::string CtxVarName;
     bool HasCompletionDoneGuard = false;
     bool UsesCompleteOrKfree = false;
     SourceLocation AnyUseLoc;
     bool AnyUseLocValid = false;
   };

   struct SchedInfo {
     std::string RecordName;
     bool HasQueueWorkWithSameCtx = false;
     bool HasWaitTimeoutOnSameCtx = false;
     bool FreesCtxOnTimeout = false;
     SourceLocation FreeLoc;
     bool FreeLocValid = false;
   };

   // Keyed by RecordName (struct tag)
   mutable std::unordered_map<std::string, WorkerInfo> WorkerByRecord;
   mutable std::unordered_map<std::string, SchedInfo> SchedByRecord;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Workqueue context race (missing completion_done)", "Concurrency")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
      void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;

   private:

      // Helper predicates and extractors
      static bool getRecordNameFromPtrType(QualType QT, std::string &OutName) {
        if (QT.isNull())
          return false;
        QualType Pointee = QT->getPointeeType();
        if (Pointee.isNull())
          return false;
        if (const auto *RT = Pointee->getAs<RecordType>()) {
          const RecordDecl *RD = RT->getDecl();
          if (!RD)
            return false;
          std::string N = RD->getNameAsString();
          if (N.empty())
            return false;
          OutName = N;
          return true;
        }
        return false;
      }

      static bool exprTextContains(const Expr *E, StringRef Name,
                                   const SourceManager &SM,
                                   const LangOptions &LO) {
        if (!E)
          return false;
        CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
        StringRef Txt = Lexer::getSourceText(Range, SM, LO);
        return Txt.contains(Name);
      }

      static const CallExpr* findCallInCond(const Expr *CondE, StringRef CalleeName) {
        if (!CondE) return nullptr;
        CondE = CondE->IgnoreParenCasts();
        if (const auto *CE = dyn_cast<CallExpr>(CondE)) {
          if (const FunctionDecl *FD = CE->getDirectCallee()) {
            if (FD->getIdentifier() && FD->getName() == CalleeName)
              return CE;
          }
        } else if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
          if (UO->getOpcode() == UO_LNot) {
            if (const auto *CE = dyn_cast<CallExpr>(UO->getSubExpr()->IgnoreParenCasts())) {
              if (const FunctionDecl *FD = CE->getDirectCallee()) {
                if (FD->getIdentifier() && FD->getName() == CalleeName)
                  return CE;
              }
            }
          }
        } else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
          const Expr *L = BO->getLHS()->IgnoreParenCasts();
          const Expr *R = BO->getRHS()->IgnoreParenCasts();
          const CallExpr *LC = dyn_cast<CallExpr>(L);
          const CallExpr *RC = dyn_cast<CallExpr>(R);
          auto IsZero = [](const Expr *E) -> bool {
            if (const auto *IL = dyn_cast<IntegerLiteral>(E))
              return IL->getValue() == 0;
            return false;
          };
          if (LC && BO->getOpcode() == BO_EQ && IsZero(R)) {
            if (const FunctionDecl *FD = LC->getDirectCallee()) {
              if (FD->getIdentifier() && FD->getName() == CalleeName)
                return LC;
            }
          }
          if (RC && BO->getOpcode() == BO_EQ && IsZero(L)) {
            if (const FunctionDecl *FD = RC->getDirectCallee()) {
              if (FD->getIdentifier() && FD->getName() == CalleeName)
                return RC;
            }
          }
        }
        return nullptr;
      }

      static bool isThenBranchTimeout(const IfStmt *IfS) {
        // Determine which branch is timeout, based on common idioms.
        // Returns true if 'then' is timeout branch, false if 'else' is timeout branch.
        // If cannot determine (e.g., no else and no negation/==0), default to 'then' as not-timeout.
        const Expr *Cond = IfS->getCond();
        Cond = Cond ? Cond->IgnoreParenCasts() : nullptr;

        // if (!wait(...)) => then is timeout
        if (const auto *UO = dyn_cast_or_null<UnaryOperator>(Cond)) {
            if (UO->getOpcode() == UO_LNot) {
              if (const auto *CE = dyn_cast<CallExpr>(UO->getSubExpr()->IgnoreParenCasts())) {
                if (const FunctionDecl *FD = CE->getDirectCallee()) {
                  if (FD->getIdentifier() && FD->getName() == "wait_for_completion_timeout")
                    return true;
                }
              }
            }
        }

        // if (wait(...) == 0) => then is timeout
        if (const auto *BO = dyn_cast_or_null<BinaryOperator>(Cond)) {
          const Expr *L = BO->getLHS()->IgnoreParenCasts();
          const Expr *R = BO->getRHS()->IgnoreParenCasts();
          auto IsZero = [](const Expr *E) -> bool {
            if (const auto *IL = dyn_cast<IntegerLiteral>(E))
              return IL->getValue() == 0;
            return false;
          };
          if (BO->getOpcode() == BO_EQ) {
            if (const auto *LC = dyn_cast<CallExpr>(L)) {
              if (const FunctionDecl *FD = LC->getDirectCallee()) {
                if (FD->getIdentifier() && FD->getName() == "wait_for_completion_timeout" && IsZero(R))
                  return true;
              }
            }
            if (const auto *RC = dyn_cast<CallExpr>(R)) {
              if (const FunctionDecl *FD = RC->getDirectCallee()) {
                if (FD->getIdentifier() && FD->getName() == "wait_for_completion_timeout" && IsZero(L))
                  return true;
              }
            }
          }
        }

        // if (wait(...)) => else is timeout
        if (const auto *CE = dyn_cast_or_null<CallExpr>(Cond)) {
          if (const FunctionDecl *FD = CE->getDirectCallee()) {
            if (FD->getIdentifier() && FD->getName() == "wait_for_completion_timeout")
              return false; // then is success, else is timeout
          }
        }

        // Default: else is timeout (conservative)
        return false;
      }

      static bool isAddrOfMemberOnCtx(const Expr *Arg,
                                      StringRef CtxVarName,
                                      StringRef MemberSubstring) {
        if (!Arg) return false;
        Arg = Arg->IgnoreParenCasts();
        const UnaryOperator *UO = dyn_cast<UnaryOperator>(Arg);
        if (!UO || UO->getOpcode() != UO_AddrOf)
          return false;

        const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
        const auto *ME = dyn_cast<MemberExpr>(Sub);
        if (!ME)
          return false;

        const ValueDecl *MD = ME->getMemberDecl();
        if (!MD)
          return false;
        std::string MName = MD->getNameAsString();
        if (MName.find(MemberSubstring.str()) == std::string::npos)
          return false;

        const Expr *Base = ME->getBase()->IgnoreParenCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
          const ValueDecl *VD = DRE->getDecl();
          if (!VD)
            return false;
          return VD->getName() == CtxVarName;
        }
        return false;
      }

      static bool getCtxFromAddrOfMember(const Expr *Arg,
                                         std::string &OutCtxVar,
                                         std::string &OutRecordName) {
        if (!Arg) return false;
        Arg = Arg->IgnoreParenCasts();
        const auto *UO = dyn_cast<UnaryOperator>(Arg);
        if (!UO || UO->getOpcode() != UO_AddrOf)
          return false;

        const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
        const auto *ME = dyn_cast<MemberExpr>(Sub);
        if (!ME)
          return false;

        const Expr *Base = ME->getBase()->IgnoreParenCasts();
        const auto *DRE = dyn_cast<DeclRefExpr>(Base);
        if (!DRE)
          return false;

        const ValueDecl *VD = DRE->getDecl();
        if (!VD)
          return false;

        OutCtxVar = VD->getNameAsString();
        return getRecordNameFromPtrType(VD->getType(), OutRecordName);
      }

      static bool isKfreeOfVar(const CallExpr *CE, StringRef VarName) {
        if (!CE) return false;
        const FunctionDecl *FD = CE->getDirectCallee();
        if (!FD || !FD->getIdentifier())
          return false;
        if (FD->getName() != "kfree")
          return false;
        if (CE->getNumArgs() < 1)
          return false;
        const Expr *A0 = CE->getArg(0)->IgnoreParenCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(A0)) {
          const ValueDecl *VD = DRE->getDecl();
          return VD && VD->getName() == VarName;
        }
        return false;
      }

      static const CallExpr* findKfreeOfVarInSubtree(const Stmt *S, StringRef VarName) {
        if (!S) return nullptr;
        if (const auto *CE = dyn_cast<CallExpr>(S)) {
          if (isKfreeOfVar(CE, VarName))
            return CE;
        }
        for (const Stmt *Child : S->children()) {
          if (!Child) continue;
          if (const CallExpr *Found = findKfreeOfVarInSubtree(Child, VarName))
            return Found;
        }
        return nullptr;
      }

      // AST scanning utilities
      static bool isContainerOfInit(const VarDecl *VD,
                                    const SourceManager &SM,
                                    const LangOptions &LO) {
        if (!VD || !VD->hasInit())
          return false;
        const Expr *Init = VD->getInit();
        return exprTextContains(Init, "container_of", SM, LO);
      }

      static std::string getCalleeName(const CallExpr *CE) {
        if (!CE) return "";
        if (const FunctionDecl *FD = CE->getDirectCallee()) {
          if (const IdentifierInfo *II = FD->getIdentifier())
            return II->getName().str();
        }
        return "";
      }

      static bool isQueueWorkLike(StringRef Name) {
        return Name == "queue_work" ||
               Name == "queue_work_on" ||
               Name == "schedule_work" ||
               Name == "queue_delayed_work" ||
               Name == "queue_delayed_work_on" ||
               Name == "schedule_delayed_work";
      }
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  const Stmt *Body = FD->getBody();
  ASTContext &ACtx = Mgr.getASTContext();
  const SourceManager &SM = ACtx.getSourceManager();
  const LangOptions &LO = ACtx.getLangOpts();

  // Worker role detection: find VarDecl initialized via container_of(...)
  bool WorkerRoleActive = false;
  std::string WorkerCtxVarName;
  std::string WorkerRecordName;

  // Scan DeclStmts to find container_of init
  for (const Stmt *Child : Body->children()) {
    if (!Child) continue;
    if (const auto *DS = dyn_cast<DeclStmt>(Child)) {
      for (const Decl *SD : DS->decls()) {
        const auto *VD = dyn_cast<VarDecl>(SD);
        if (!VD) continue;
        // Must be pointer to some struct
        std::string RN;
        if (!getRecordNameFromPtrType(VD->getType(), RN))
          continue;
        if (!VD->hasInit())
          continue;
        if (isContainerOfInit(VD, SM, LO)) {
          WorkerRoleActive = true;
          WorkerCtxVarName = VD->getNameAsString();
          WorkerRecordName = RN;
          break;
        }
      }
    }
    if (WorkerRoleActive)
      break;
  }

  // Prepare aggregation holders for this function
  bool FoundCompletionDoneGuard = false;
  bool FoundUsesCompleteOrKfree = false;
  SourceLocation FirstUseLoc;

  // Scheduler role detection structures for this function
  // Map RecordName -> ctx var name used with wait/queue
  std::unordered_map<std::string, std::string> RecToCtxVar_Wait;
  std::unordered_map<std::string, bool> RecHasWait;
  std::unordered_map<std::string, bool> RecHasQueue;
  std::unordered_map<std::string, SourceLocation> RecTimeoutFreeLoc;
  std::unordered_map<std::string, bool> RecHasTimeoutFree;

  // Walk all CallExpr and IfStmt in the function body to collect info
  // Simple recursive lambda
  std::function<void(const Stmt*)> Walk;
  Walk = [&](const Stmt *S) {
    if (!S) return;

    if (const auto *CE = dyn_cast<CallExpr>(S)) {
      std::string Callee = getCalleeName(CE);

      if (WorkerRoleActive) {
        if (Callee == "completion_done") {
          if (CE->getNumArgs() >= 1 &&
              isAddrOfMemberOnCtx(CE->getArg(0), WorkerCtxVarName, "compl")) {
            FoundCompletionDoneGuard = true;
          }
        } else if (Callee == "complete") {
          if (CE->getNumArgs() >= 1 &&
              isAddrOfMemberOnCtx(CE->getArg(0), WorkerCtxVarName, "compl")) {
            if (!FoundUsesCompleteOrKfree) {
              FirstUseLoc = CE->getBeginLoc();
            }
            FoundUsesCompleteOrKfree = true;
          }
        } else if (Callee == "kfree") {
          if (CE->getNumArgs() >= 1) {
            const Expr *A0 = CE->getArg(0)->IgnoreParenCasts();
            if (const auto *DRE = dyn_cast<DeclRefExpr>(A0)) {
              if (const ValueDecl *VD = DRE->getDecl()) {
                if (VD->getName() == WorkerCtxVarName) {
                  if (!FoundUsesCompleteOrKfree) {
                    FirstUseLoc = CE->getBeginLoc();
                  }
                  FoundUsesCompleteOrKfree = true;
                }
              }
            }
          }
        }
      }

      // Scheduler: wait_for_completion_timeout to capture ctx and record
      if (Callee == "wait_for_completion_timeout") {
        if (CE->getNumArgs() >= 1) {
          std::string CtxVar, RecName;
          if (getCtxFromAddrOfMember(CE->getArg(0), CtxVar, RecName)) {
            RecToCtxVar_Wait[RecName] = CtxVar;
            RecHasWait[RecName] = true;
          }
        }
      }

      // Scheduler: queue_* or schedule_* with &ctx->work
      if (isQueueWorkLike(Callee)) {
        for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
          const Expr *Arg = CE->getArg(i);
          Arg = Arg ? Arg->IgnoreParenCasts() : nullptr;
          const auto *UO = dyn_cast_or_null<UnaryOperator>(Arg);
          if (!UO || UO->getOpcode() != UO_AddrOf)
            continue;
          const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
          const auto *ME = dyn_cast<MemberExpr>(Sub);
          if (!ME)
            continue;
          const ValueDecl *MD = ME->getMemberDecl();
          if (!MD)
            continue;
          std::string MemName = MD->getNameAsString();
          if (MemName.find("work") == std::string::npos)
            continue;
          const Expr *Base = ME->getBase()->IgnoreParenCasts();
          const auto *DRE = dyn_cast<DeclRefExpr>(Base);
          if (!DRE)
            continue;
          const ValueDecl *VD = DRE->getDecl();
          if (!VD)
            continue;
          std::string CtxVar = VD->getNameAsString();
          std::string RecName;
          if (getRecordNameFromPtrType(VD->getType(), RecName)) {
            RecHasQueue[RecName] = true;
            // If no wait seen yet, we may not know if it's the same ctx, but we correlate by RecordName later.
          }
        }
      }
    } else if (const auto *IfS = dyn_cast<IfStmt>(S)) {
      // If condition involves wait_for_completion_timeout
      const CallExpr *WaitC = findCallInCond(IfS->getCond(), "wait_for_completion_timeout");
      if (WaitC && WaitC->getNumArgs() >= 1) {
        std::string CtxVar, RecName;
        if (getCtxFromAddrOfMember(WaitC->getArg(0), CtxVar, RecName)) {
          RecToCtxVar_Wait[RecName] = CtxVar;
          RecHasWait[RecName] = true;

          bool ThenIsTimeout = isThenBranchTimeout(IfS);
          const Stmt *TimeoutBranch = ThenIsTimeout ? IfS->getThen() : IfS->getElse();
          if (TimeoutBranch) {
            if (const CallExpr *KF = findKfreeOfVarInSubtree(TimeoutBranch, CtxVar)) {
              RecHasTimeoutFree[RecName] = true;
              RecTimeoutFreeLoc[RecName] = KF->getBeginLoc();
            }
          }
        }
      }
    }

    for (const Stmt *Child : S->children())
      Walk(Child);
  };

  Walk(Body);

  // Commit worker info if applicable
  if (WorkerRoleActive) {
    auto It = WorkerByRecord.find(WorkerRecordName);
    if (It == WorkerByRecord.end()) {
      WorkerInfo WI;
      WI.RecordName = WorkerRecordName;
      WI.CtxVarName = WorkerCtxVarName;
      WI.HasCompletionDoneGuard = FoundCompletionDoneGuard;
      WI.UsesCompleteOrKfree = FoundUsesCompleteOrKfree;
      WI.AnyUseLoc = FirstUseLoc;
      WI.AnyUseLocValid = FoundUsesCompleteOrKfree;
      WorkerByRecord.emplace(WorkerRecordName, WI);
    } else {
      // Merge conservatively
      It->second.HasCompletionDoneGuard = It->second.HasCompletionDoneGuard || FoundCompletionDoneGuard;
      if (FoundUsesCompleteOrKfree) {
        It->second.UsesCompleteOrKfree = true;
        if (!It->second.AnyUseLocValid) {
          It->second.AnyUseLoc = FirstUseLoc;
          It->second.AnyUseLocValid = true;
        }
      }
    }
  }

  // Commit scheduler info for each record that has wait+queue and has timeout-free
  for (const auto &P : RecHasWait) {
    const std::string &RecName = P.first;
    bool HasWait = P.second;
    bool HasQueue = RecHasQueue.count(RecName) ? RecHasQueue[RecName] : false;
    bool HasFree = RecHasTimeoutFree.count(RecName) ? RecHasTimeoutFree[RecName] : false;
    if (HasWait && HasQueue && HasFree) {
      auto It = SchedByRecord.find(RecName);
      if (It == SchedByRecord.end()) {
        SchedInfo SI;
        SI.RecordName = RecName;
        SI.HasQueueWorkWithSameCtx = true;
        SI.HasWaitTimeoutOnSameCtx = true;
        SI.FreesCtxOnTimeout = true;
        SI.FreeLoc = RecTimeoutFreeLoc[RecName];
        SI.FreeLocValid = true;
        SchedByRecord.emplace(RecName, SI);
      } else {
        It->second.HasQueueWorkWithSameCtx = true;
        It->second.HasWaitTimeoutOnSameCtx = true;
        It->second.FreesCtxOnTimeout = true;
        if (!It->second.FreeLocValid && RecTimeoutFreeLoc.count(RecName)) {
          It->second.FreeLoc = RecTimeoutFreeLoc[RecName];
          It->second.FreeLocValid = true;
        }
      }
    }
  }
}

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
  // Correlate worker and scheduler info by RecordName
  for (const auto &SP : SchedByRecord) {
    const std::string &RecName = SP.first;
    const SchedInfo &SI = SP.second;

    if (!(SI.HasWaitTimeoutOnSameCtx && SI.HasQueueWorkWithSameCtx && SI.FreesCtxOnTimeout && SI.FreeLocValid))
      continue;

    auto WIt = WorkerByRecord.find(RecName);
    if (WIt == WorkerByRecord.end())
      continue;

    const WorkerInfo &WI = WIt->second;
    if (!(WI.UsesCompleteOrKfree && !WI.HasCompletionDoneGuard))
      continue;

    // Report
    PathDiagnosticLocation Loc =
        PathDiagnosticLocation::createBegin(SI.FreeLoc, BR.getSourceManager());

    auto R = std::make_unique<BasicBugReport>(
        *BT,
        "Workqueue context may be freed on timeout while worker still uses it; missing completion_done() guard",
        Loc);
    BR.emitReport(std::move(R));
  }

  // Clear collected data to avoid cross-TU mixing (defensive)
  WorkerByRecord.clear();
  SchedByRecord.clear();
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects race: scheduler frees workqueue context on timeout while worker uses it without completion_done() guard",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
