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
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include <utility>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed for this checker.
namespace {

struct WorkerBodyInfo {
  bool HasCompletionDone = false;
  bool HasUseOrFree = false; // complete()/complete_all()/kfree()/kvfree()
  const Stmt *FirstUseOrFreeStmt = nullptr; // for reporting location
};

// The checker scans AST bodies and correlates submitter and worker functions.
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

  // Cache of worker function analysis results.
  mutable llvm::DenseMap<const FunctionDecl *, WorkerBodyInfo> WorkerInfoMap;

  // Set of worker functions that are "at risk" due to submitter pattern
  // (wait_for_completion_timeout + kfree of the same context).
  mutable llvm::DenseSet<const FunctionDecl *> RiskyWorkers;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Worker may use/free context after submitter timeout",
                       "Concurrency")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  // Helpers
  static const FunctionDecl *getDirectCallee(const CallExpr *CE) {
    if (!CE) return nullptr;
    return CE->getDirectCallee();
  }

  static bool isCallNamed(const CallExpr *CE, StringRef Name) {
    if (!CE) return false;
    if (const FunctionDecl *FD = getDirectCallee(CE)) {
      return FD->getName() == Name;
    }
    return false;
  }

  static const FunctionDecl *getFunctionDeclFromExpr(const Expr *E) {
    if (!E) return nullptr;
    E = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *FD = dyn_cast<FunctionDecl>(DRE->getDecl()))
        return FD;
    }
    return nullptr;
  }

  // Return the root ValueDecl for expressions like:
  //   - owner
  //   - owner->field
  //   - (&owner->field)
  //   - (owner).field
  static const ValueDecl *getRootBaseDeclFromMember(const Expr *E) {
    if (!E) return nullptr;
    E = E->IgnoreParenImpCasts();

    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf || UO->getOpcode() == UO_Deref)
        return getRootBaseDeclFromMember(UO->getSubExpr());
    }

    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      const Expr *Base = ME->getBase();
      if (!Base) return nullptr;
      return getRootBaseDeclFromMember(Base);
    }

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      return DRE->getDecl();
    }

    return nullptr;
  }

  // Get owner decl from an expression like &owner->field or &owner.field.
  static const ValueDecl *getOwnerDeclFromAddrOfMember(const Expr *E) {
    if (!E) return nullptr;
    E = E->IgnoreParenImpCasts();
    const UnaryOperator *UO = dyn_cast<UnaryOperator>(E);
    if (!UO || UO->getOpcode() != UO_AddrOf)
      return nullptr;

    const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
    const MemberExpr *ME = dyn_cast<MemberExpr>(Sub);
    if (!ME)
      return nullptr;

    // Optional: ensure the member name looks like a work field when used for INIT_WORK
    return getRootBaseDeclFromMember(ME);
  }

  // Does expr E ultimately refer to the same root decl as Owner?
  static bool exprRootsToOwner(const Expr *E, const ValueDecl *Owner) {
    if (!E || !Owner) return false;
    const ValueDecl *VD = nullptr;

    E = E->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf || UO->getOpcode() == UO_Deref)
        return exprRootsToOwner(UO->getSubExpr(), Owner);
    }

    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      VD = getRootBaseDeclFromMember(ME);
    } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      VD = DRE->getDecl();
    } else {
      VD = getRootBaseDeclFromMember(E);
    }

    return VD && VD == Owner;
  }

  static bool occursAfter(SourceLocation A, SourceLocation B,
                          const SourceManager &SM) {
    if (A.isInvalid() || B.isInvalid())
      return false;
    // True if B is before A => A occurs after B.
    return SM.isBeforeInTranslationUnit(B, A);
  }

  void analyzeWorkerBody(const FunctionDecl *FD, AnalysisManager &Mgr,
                         BugReporter &BR) const;

  void analyzeSubmitterBody(const FunctionDecl *FD, AnalysisManager &Mgr,
                            BugReporter &BR) const;

  void maybeReport(const FunctionDecl *WorkerFD, AnalysisManager &Mgr,
                   BugReporter &BR, const WorkerBodyInfo &Info) const;
};

// Scan a function body as a worker: does it call completion_done? does it
// call complete()/complete_all()/kfree()/kvfree()?
void SAGenTestChecker::analyzeWorkerBody(const FunctionDecl *FD,
                                         AnalysisManager &Mgr,
                                         BugReporter &BR) const {
  if (!FD || !FD->hasBody())
    return;

  auto It = WorkerInfoMap.find(FD);
  if (It != WorkerInfoMap.end()) {
    // Already analyzed
    return;
  }

  WorkerBodyInfo Info;

  const Stmt *Body = FD->getBody();

  class WorkerScanner : public RecursiveASTVisitor<WorkerScanner> {
  public:
    WorkerBodyInfo &I;
    WorkerScanner(WorkerBodyInfo &InfoRef) : I(InfoRef) {}
    bool VisitCallExpr(CallExpr *CE) {
      if (!CE) return true;

      if (const FunctionDecl *Callee = CE->getDirectCallee()) {
        StringRef Name = Callee->getName();
        if (Name == "completion_done") {
          I.HasCompletionDone = true;
        } else if (Name == "complete" || Name == "complete_all" ||
                   Name == "kfree" || Name == "kvfree") {
          if (!I.HasUseOrFree) {
            I.HasUseOrFree = true;
            I.FirstUseOrFreeStmt = CE;
          }
        }
      }
      return true;
    }
  } Scanner(Info);

  Scanner.TraverseStmt(const_cast<Stmt *>(Body));

  WorkerInfoMap[FD] = Info;

  // If this worker is marked risky, maybe report now.
  if (RiskyWorkers.count(FD)) {
    maybeReport(FD, Mgr, BR, Info);
  }
}

// Scan a function that schedules workers and waits with timeout, then frees
// the context. If that pattern is found, mark the associated worker function
// as risky.
void SAGenTestChecker::analyzeSubmitterBody(const FunctionDecl *FD,
                                            AnalysisManager &Mgr,
                                            BugReporter &BR) const {
  if (!FD || !FD->hasBody())
    return;

  const Stmt *Body = FD->getBody();
  const SourceManager &SM = BR.getSourceManager();

  struct OwnerRecord {
    const FunctionDecl *WorkerFD = nullptr; // from INIT_WORK or similar
    llvm::SmallVector<SourceLocation, 4> WaitLocs;
    llvm::SmallVector<SourceLocation, 4> FreeLocs;
    // Store which field name was used in INIT_WORK first arg; used to ensure it's a work field
    bool IsWorkLike = false;
  };

  llvm::DenseMap<const ValueDecl *, OwnerRecord> OwnerMap;

  class SubmitterScanner : public RecursiveASTVisitor<SubmitterScanner> {
  public:
    const SourceManager &SM;
    llvm::DenseMap<const ValueDecl *, OwnerRecord> &OM;
    SubmitterScanner(const SourceManager &SMgr,
                     llvm::DenseMap<const ValueDecl *, OwnerRecord> &OwnerM)
        : SM(SMgr), OM(OwnerM) {}

    bool VisitCallExpr(CallExpr *CE) {
      if (!CE) return true;

      const FunctionDecl *Callee = CE->getDirectCallee();
      if (!Callee) return true;

      StringRef Name = Callee->getName();

      // Detect INIT_WORK-like: first arg should be &owner->work, second is worker
      if (Name == "INIT_WORK" || Name == "__INIT_WORK" ||
          Name == "INIT_WORK_ONSTACK" || Name == "init_work") {

        const Expr *Arg0 = (CE->getNumArgs() >= 1) ? CE->getArg(0) : nullptr;
        const Expr *Arg1 = (CE->getNumArgs() >= 2) ? CE->getArg(1) : nullptr;
        if (!Arg0 || !Arg1)
          return true;

        // Check Arg0 is &owner->work-like
        const Expr *A0 = Arg0->IgnoreParenImpCasts();
        const UnaryOperator *UO = dyn_cast<UnaryOperator>(A0);
        if (!UO || UO->getOpcode() != UO_AddrOf)
          return true;

        const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
        const MemberExpr *ME = dyn_cast<MemberExpr>(Sub);
        if (!ME)
          return true;

        bool IsWorkLike = false;
        if (const ValueDecl *MD = ME->getMemberDecl()) {
          StringRef FieldName = MD->getName();
          if (FieldName.contains("work"))
            IsWorkLike = true;
        }

        const ValueDecl *Owner = SAGenTestChecker::getRootBaseDeclFromMember(ME);
        if (!Owner)
          return true;

        const FunctionDecl *WorkerFD =
            SAGenTestChecker::getFunctionDeclFromExpr(Arg1);
        // Record even if worker is null (keep owner for later events)
        OwnerRecord &Rec = OM[Owner];
        if (WorkerFD)
          Rec.WorkerFD = WorkerFD;
        Rec.IsWorkLike |= IsWorkLike;
      }

      // Detect wait_for_completion_timeout(&owner->compl, ...)
      if (Name == "wait_for_completion_timeout") {
        const Expr *Arg0 = (CE->getNumArgs() >= 1) ? CE->getArg(0) : nullptr;
        if (Arg0) {
          const ValueDecl *Owner =
              SAGenTestChecker::getOwnerDeclFromAddrOfMember(Arg0);
          if (Owner) {
            OwnerRecord &Rec = OM[Owner];
            Rec.WaitLocs.push_back(CE->getExprLoc());
          }
        }
      }

      // Detect kfree(owner) or kvfree(owner)
      if (Name == "kfree" || Name == "kvfree") {
        const Expr *Arg0 = (CE->getNumArgs() >= 1) ? CE->getArg(0) : nullptr;
        if (Arg0) {
          // Try to match to any known owner, or infer owner from Arg0.
          // Prefer direct inference:
          const ValueDecl *DirectOwner = nullptr;
          const Expr *E0 = Arg0->IgnoreParenImpCasts();
          if (const auto *DRE = dyn_cast<DeclRefExpr>(E0)) {
            DirectOwner = DRE->getDecl();
          } else {
            DirectOwner = SAGenTestChecker::getRootBaseDeclFromMember(E0);
          }

          if (DirectOwner) {
            OwnerRecord &Rec = OM[DirectOwner];
            Rec.FreeLocs.push_back(CE->getExprLoc());
          } else {
            // Otherwise, try to match any existing owner by root-compare.
            for (auto &P : OM) {
              if (SAGenTestChecker::exprRootsToOwner(Arg0, P.first)) {
                P.second.FreeLocs.push_back(CE->getExprLoc());
              }
            }
          }
        }
      }

      return true;
    }
  } Scanner(SM, OwnerMap);

  Scanner.TraverseStmt(const_cast<Stmt *>(Body));

  // After scan: find owners that have worker + wait + kfree after wait.
  for (const auto &Entry : OwnerMap) {
    const ValueDecl *Owner = Entry.first;
    const OwnerRecord &Rec = Entry.second;

    if (!Rec.WorkerFD)
      continue;

    if (Rec.WaitLocs.empty() || Rec.FreeLocs.empty())
      continue;

    // At least one kfree after some wait.
    bool HasAfter = false;
    for (auto FL : Rec.FreeLocs) {
      for (auto WL : Rec.WaitLocs) {
        if (occursAfter(FL, WL, SM)) {
          HasAfter = true;
          break;
        }
      }
      if (HasAfter) break;
    }

    if (!HasAfter)
      continue;

    // Mark worker as risky.
    RiskyWorkers.insert(Rec.WorkerFD);

    // If already analyzed worker body, maybe report now.
    auto It = WorkerInfoMap.find(Rec.WorkerFD);
    if (It != WorkerInfoMap.end()) {
      maybeReport(Rec.WorkerFD, Mgr, BR, It->second);
    }
  }
}

void SAGenTestChecker::maybeReport(const FunctionDecl *WorkerFD,
                                   AnalysisManager &Mgr, BugReporter &BR,
                                   const WorkerBodyInfo &Info) const {
  if (!WorkerFD)
    return;

  if (!RiskyWorkers.count(WorkerFD))
    return;

  if (!Info.HasUseOrFree)
    return;

  if (Info.HasCompletionDone)
    return;

  // Report: Worker may use/free context after submitter timeout; missing completion_done()
  const Stmt *S = Info.FirstUseOrFreeStmt ? Info.FirstUseOrFreeStmt
                                          : WorkerFD->getBody();
  AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(WorkerFD);
  PathDiagnosticLocation Loc =
      PathDiagnosticLocation::createBegin(S, BR.getSourceManager(), ADC);

  BR.EmitBasicReport(
      WorkerFD, this,
      "Worker may use/free context after submitter timeout",
      "Concurrency",
      "Missing completion_done() check in workqueue worker; submitter may free "
      "the context after wait_for_completion_timeout.",
      Loc);
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  // Analyze as worker to collect info (if it is a worker).
  analyzeWorkerBody(FD, Mgr, BR);

  // Analyze as submitter to find risky workers.
  analyzeSubmitterBody(FD, Mgr, BR);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing completion_done() guard in workqueue worker when submitter may free context after wait_for_completion_timeout",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
