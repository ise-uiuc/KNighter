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
#include "clang/AST/ASTContext.h"
#include "clang/Lex/Lexer.h"
#include <string>
#include <utility>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed for this checker.
 // If necessary

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Uncoordinated free after timed wait", "Concurrency")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:

      // Helpers
      static bool isCallNamed(const CallExpr *CE, StringRef Name, CheckerContext &C);
      static const CallExpr *findCallByNameInStmt(const Stmt *S, StringRef Name, CheckerContext &C);
      static bool extractBaseVarNameFromCompletionArg(const Expr *Arg, std::string &OutName);
      static const IfStmt *getEnclosingIf(const Stmt *Condition, CheckerContext &C);

      static const Stmt *getPrevSibling(const CompoundStmt *CS, const Stmt *S);
      static bool findPrevWaitAssignment(const CompoundStmt *CS, const IfStmt *IfS,
                                         const std::string &VarName,
                                         const CallExpr *&OutWaitCall,
                                         const BinaryOperator *&OutAssign,
                                         const DeclStmt *&OutDecl);
      static bool isZeroExpr(const Expr *E, CheckerContext &C);
      static const Stmt *determineTimeoutBranchForDirectCall(const IfStmt *IfS, const Stmt *CondS, CheckerContext &C);
      static const Stmt *determineTimeoutBranchForVarCond(const IfStmt *IfS, const Expr *CondE, CheckerContext &C);

      static bool branchContainsFreeOfBaseName(const Stmt *S, StringRef BaseName, CheckerContext &C, const CallExpr **FoundFree = nullptr);
      static bool stmtContainsFreeOfBaseName(const Stmt *S, StringRef BaseName, CheckerContext &C, const CallExpr **FoundFree = nullptr);
      static bool compoundHasQueueWorkWithBaseNameBefore(const CompoundStmt *CS, const IfStmt *IfS, StringRef BaseName, CheckerContext &C);
      static bool subsequentStatementsContainFree(const CompoundStmt *CS, const IfStmt *IfS, StringRef BaseName, CheckerContext &C, const CallExpr **FoundFree = nullptr);

      void emitReport(CheckerContext &C, StringRef Msg, const Stmt *LocStmt) const;
};

// ============= Helper Implementations =============

bool SAGenTestChecker::isCallNamed(const CallExpr *CE, StringRef Name, CheckerContext &C) {
  if (!CE) return false;
  const Expr *Callee = CE->getCallee();
  if (!Callee) return false;
  // Use source-text based name check as suggested.
  return ExprHasName(Callee, Name, C);
}

const CallExpr *SAGenTestChecker::findCallByNameInStmt(const Stmt *S, StringRef Name, CheckerContext &C) {
  if (!S) return nullptr;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (isCallNamed(CE, Name, C))
      return CE;
  }
  for (const Stmt *Child : S->children()) {
    if (const CallExpr *Found = findCallByNameInStmt(Child, Name, C))
      return Found;
  }
  return nullptr;
}

bool SAGenTestChecker::extractBaseVarNameFromCompletionArg(const Expr *Arg, std::string &OutName) {
  if (!Arg) return false;
  const Expr *E = Arg->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_AddrOf)
      E = UO->getSubExpr()->IgnoreParenImpCasts();
  }
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
    // Drill through nested MemberExpr if present.
    while (const auto *InnerME = dyn_cast<MemberExpr>(Base)) {
      Base = InnerME->getBase()->IgnoreParenImpCasts();
    }
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      OutName = DRE->getDecl()->getNameAsString();
      return !OutName.empty();
    }
  }
  // Fallback: look for a DeclRefExpr anywhere within Arg.
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(Arg)) {
    OutName = DRE->getDecl()->getNameAsString();
    return !OutName.empty();
  }
  return false;
}

const IfStmt *SAGenTestChecker::getEnclosingIf(const Stmt *Condition, CheckerContext &C) {
  return findSpecificTypeInParents<IfStmt>(Condition, C);
}

const Stmt *SAGenTestChecker::getPrevSibling(const CompoundStmt *CS, const Stmt *S) {
  if (!CS || !S) return nullptr;
  const Stmt *Prev = nullptr;
  for (const Stmt *Child : CS->body()) {
    if (Child == S)
      return Prev;
    Prev = Child;
  }
  return nullptr;
}

bool SAGenTestChecker::findPrevWaitAssignment(const CompoundStmt *CS, const IfStmt *IfS,
                                              const std::string &VarName,
                                              const CallExpr *&OutWaitCall,
                                              const BinaryOperator *&OutAssign,
                                              const DeclStmt *&OutDecl) {
  OutWaitCall = nullptr;
  OutAssign = nullptr;
  OutDecl = nullptr;
  if (!CS || !IfS) return false;

  const Stmt *Prev = getPrevSibling(CS, IfS);
  if (!Prev) return false;

  // Case 1: Declaration with initializer
  if (const auto *DS = dyn_cast<DeclStmt>(Prev)) {
    for (const Decl *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (VD->getName() == VarName && VD->hasInit()) {
          if (const auto *CE = dyn_cast<CallExpr>(VD->getInit()->IgnoreParenImpCasts())) {
            OutWaitCall = CE;
            OutDecl = DS;
            return true;
          }
        }
      }
    }
  }

  // Case 2: Assignment
  if (const auto *BO = dyn_cast<BinaryOperator>(Prev)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl()->getName() == VarName) {
          if (const auto *CE = dyn_cast<CallExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
            OutWaitCall = CE;
            OutAssign = BO;
            return true;
          }
        }
      }
    }
  }

  return false;
}

bool SAGenTestChecker::isZeroExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E->IgnoreParenImpCasts(), C)) {
    return Val == 0;
  }
  return false;
}

const Stmt *SAGenTestChecker::determineTimeoutBranchForDirectCall(const IfStmt *IfS, const Stmt *CondS, CheckerContext &C) {
  if (!IfS || !CondS) return nullptr;
  // Handle "!wait_for_completion_timeout(...)"
  if (const auto *UO = dyn_cast<UnaryOperator>(CondS)) {
    if (UO->getOpcode() == UO_LNot) {
      if (findCallByNameInStmt(UO->getSubExpr(), "wait_for_completion_timeout", C)) {
        return IfS->getThen(); // !ret -> Then is timeout
      }
    }
  }
  // Handle "wait_for_completion_timeout(...)" being used directly
  if (findCallByNameInStmt(CondS, "wait_for_completion_timeout", C)) {
    return IfS->getElse(); // non-zero -> success in Then, Else is timeout
  }
  return nullptr;
}

const Stmt *SAGenTestChecker::determineTimeoutBranchForVarCond(const IfStmt *IfS, const Expr *CondE, CheckerContext &C) {
  if (!IfS || !CondE) return nullptr;
  CondE = CondE->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      // if (!ret) -> Then is timeout
      return IfS->getThen();
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSZero = isZeroExpr(LHS, C);
      bool RHSZero = isZeroExpr(RHS, C);
      if ((BO->getOpcode() == BO_EQ) && (LHSZero ^ RHSZero)) {
        // ret == 0 -> Then is timeout
        return IfS->getThen();
      }
      if ((BO->getOpcode() == BO_NE) && (LHSZero ^ RHSZero)) {
        // ret != 0 -> Else is timeout
        return IfS->getElse();
      }
    }
  } else if (isa<DeclRefExpr>(CondE)) {
    // if (ret) -> Else is timeout (ret == 0)
    return IfS->getElse();
  }

  return nullptr;
}

bool SAGenTestChecker::stmtContainsFreeOfBaseName(const Stmt *S, StringRef BaseName, CheckerContext &C, const CallExpr **FoundFree) {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (isCallNamed(CE, "kfree", C) || isCallNamed(CE, "kvfree", C)) {
      if (CE->getNumArgs() >= 1) {
        const Expr *Arg0 = CE->getArg(0);
        if (Arg0 && ExprHasName(Arg0, BaseName, C)) {
          if (FoundFree) *FoundFree = CE;
          return true;
        }
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (stmtContainsFreeOfBaseName(Child, BaseName, C, FoundFree))
      return true;
  }
  return false;
}

bool SAGenTestChecker::branchContainsFreeOfBaseName(const Stmt *S, StringRef BaseName, CheckerContext &C, const CallExpr **FoundFree) {
  return stmtContainsFreeOfBaseName(S, BaseName, C, FoundFree);
}

bool SAGenTestChecker::compoundHasQueueWorkWithBaseNameBefore(const CompoundStmt *CS, const IfStmt *IfS, StringRef BaseName, CheckerContext &C) {
  if (!CS || !IfS) return false;
  for (const Stmt *Child : CS->body()) {
    if (Child == IfS)
      break;

    // Look for queue_* calls
    const CallExpr *CE = nullptr;
    if ((CE = findCallByNameInStmt(Child, "queue_work_on", C)) ||
        (CE = findCallByNameInStmt(Child, "queue_work", C)) ||
        (CE = findCallByNameInStmt(Child, "queue_delayed_work_on", C)) ||
        (CE = findCallByNameInStmt(Child, "queue_delayed_work", C))) {
      unsigned WorkArgIdx = 0;
      // Determine the index of the "work" argument
      if (ExprHasName(CE->getCallee(), "queue_work_on", C))
        WorkArgIdx = 2;
      else if (ExprHasName(CE->getCallee(), "queue_work", C))
        WorkArgIdx = 1;
      else if (ExprHasName(CE->getCallee(), "queue_delayed_work_on", C))
        WorkArgIdx = 2;
      else if (ExprHasName(CE->getCallee(), "queue_delayed_work", C))
        WorkArgIdx = 1;

      if (CE->getNumArgs() > WorkArgIdx) {
        const Expr *WorkArg = CE->getArg(WorkArgIdx);
        if (!WorkArg) continue;
        // Check the work argument contains BaseName and a member named "work"
        if (ExprHasName(WorkArg, BaseName, C) && ExprHasName(WorkArg, "work", C)) {
          return true;
        }
      }
    }
  }
  return false;
}

bool SAGenTestChecker::subsequentStatementsContainFree(const CompoundStmt *CS, const IfStmt *IfS, StringRef BaseName, CheckerContext &C, const CallExpr **FoundFree) {
  if (!CS || !IfS) return false;
  bool FoundIf = false;
  for (const Stmt *Child : CS->body()) {
    if (!FoundIf) {
      if (Child == IfS)
        FoundIf = true;
      continue;
    }
    if (stmtContainsFreeOfBaseName(Child, BaseName, C, FoundFree))
      return true;
  }
  return false;
}

// ============= Main Callback =============
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition) return;

  const IfStmt *IfS = getEnclosingIf(Condition, C);
  if (!IfS) return;

  // Case 1: Direct call to wait_for_completion_timeout in the condition
  const CallExpr *DirectCall = findCallByNameInStmt(Condition, "wait_for_completion_timeout", C);

  std::string BaseName;
  const Stmt *TimeoutBranch = nullptr;

  if (DirectCall) {
    // Extract base from first argument (&ctx->done / &ctx->compl)
    if (DirectCall->getNumArgs() >= 1) {
      if (!extractBaseVarNameFromCompletionArg(DirectCall->getArg(0), BaseName))
        return;
    } else {
      return;
    }
    // Determine timeout branch
    TimeoutBranch = determineTimeoutBranchForDirectCall(IfS, Condition, C);
    if (!TimeoutBranch) return;
  } else {
    // Case 2: Variable used in the condition
    const DeclRefExpr *CondVar = findSpecificTypeInChildren<DeclRefExpr>(Condition);
    if (!CondVar) return;

    std::string VarName = CondVar->getDecl()->getNameAsString();
    const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IfS, C);
    if (!CS) return;

    const CallExpr *PrevWaitCall = nullptr;
    const BinaryOperator *PrevAssign = nullptr;
    const DeclStmt *PrevDecl = nullptr;

    if (!findPrevWaitAssignment(CS, IfS, VarName, PrevWaitCall, PrevAssign, PrevDecl))
      return;

    if (!PrevWaitCall || !isCallNamed(PrevWaitCall, "wait_for_completion_timeout", C))
      return;

    if (PrevWaitCall->getNumArgs() >= 1) {
      if (!extractBaseVarNameFromCompletionArg(PrevWaitCall->getArg(0), BaseName))
        return;
    } else {
      return;
    }

    // Determine timeout branch based on the condition expression
    const Expr *CondE = dyn_cast<Expr>(Condition);
    if (!CondE) return;
    TimeoutBranch = determineTimeoutBranchForVarCond(IfS, CondE, C);
    if (!TimeoutBranch) return;
  }

  // Reduce FPs: confirm earlier queue_work(..., &BaseName->work/*...*/)
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IfS, C);
  if (!CS) return;
  if (!compoundHasQueueWorkWithBaseNameBefore(CS, IfS, BaseName, C))
    return;

  // Identify success branch
  const Stmt *SuccessBranch = (TimeoutBranch == IfS->getThen()) ? IfS->getElse() : IfS->getThen();

  // Scan for frees
  const CallExpr *FreeCETimeout = nullptr;
  const CallExpr *FreeCESuccess = nullptr;
  const CallExpr *FreeCEAfter = nullptr;

  bool FreeInTimeout = TimeoutBranch ? branchContainsFreeOfBaseName(TimeoutBranch, BaseName, C, &FreeCETimeout) : false;
  bool FreeInSuccess = SuccessBranch ? branchContainsFreeOfBaseName(SuccessBranch, BaseName, C, &FreeCESuccess) : false;
  bool FreeAfterIf   = subsequentStatementsContainFree(CS, IfS, BaseName, C, &FreeCEAfter);

  // Reporting logic
  if (FreeInTimeout && FreeInSuccess) {
    emitReport(C, "Freeing work context in both timeout and success paths", FreeCETimeout ? static_cast<const Stmt*>(FreeCETimeout) : static_cast<const Stmt*>(IfS));
  } else if (FreeInTimeout) {
    emitReport(C, "Freeing work context on timeout after wait_for_completion_timeout()", FreeCETimeout ? static_cast<const Stmt*>(FreeCETimeout) : static_cast<const Stmt*>(IfS));
  } else if (FreeAfterIf) {
    emitReport(C, "Unconditional free of work context after timed wait", FreeCEAfter ? static_cast<const Stmt*>(FreeCEAfter) : static_cast<const Stmt*>(IfS));
  }
}

void SAGenTestChecker::emitReport(CheckerContext &C, StringRef Msg, const Stmt *LocStmt) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (LocStmt)
    R->addRange(LocStmt->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing a workqueue context on timeout after wait_for_completion_timeout(), which races with the worker",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
