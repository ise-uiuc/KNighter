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
#include "clang/Lex/Lexer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/ParentMapContext.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Freeing shared gsm tx list without tx_lock", "Concurrency")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // --- Helpers for text and matching ---
      static std::string getNodeText(const Stmt *S, ASTContext &AC);
      static std::string getNodeText(const Expr *E, ASTContext &AC);

      static bool isCallNamed(const CallExpr *CE, StringRef Name);
      static bool stmtContainsText(const Stmt *S, StringRef Sub, ASTContext &AC);

      static bool memberExprHasField(const MemberExpr *ME, StringRef FieldName);

      static const MemberExpr *findMemberExprWithField(const Stmt *S,
                                                       ArrayRef<StringRef> FieldNames);
      static const CallExpr *findCallInStmtByName(const Stmt *S, StringRef Name);

      static void collectAllCalls(const Stmt *S, llvm::SmallVectorImpl<const CallExpr*> &Out);

      static bool stmtHasSpinLockAcquireOnTxLock(const Stmt *S, StringRef BaseText, ASTContext &AC);

      static const CompoundStmt *findNearestCompoundAncestor(ASTContext &AC, const Stmt *S);
      static bool compoundHasPrecedingLock(const CompoundStmt *CS, const Stmt *Child,
                                           StringRef BaseText, ASTContext &AC);

      static bool loopOrContextHasTxLock(const ForStmt *FS, const Expr *Base, ASTContext &AC);

      // Main per-ForStmt analysis
      void analyzeForStmt(const ForStmt *FS, const Decl *D,
                          AnalysisManager &Mgr, BugReporter &BR) const;
};

// --------- Implementation ----------

std::string SAGenTestChecker::getNodeText(const Stmt *S, ASTContext &AC) {
  if (!S) return std::string();
  const SourceManager &SM = AC.getSourceManager();
  CharSourceRange Range = CharSourceRange::getTokenRange(S->getSourceRange());
  StringRef Text = Lexer::getSourceText(Range, SM, AC.getLangOpts());
  return Text.str();
}

std::string SAGenTestChecker::getNodeText(const Expr *E, ASTContext &AC) {
  return getNodeText(static_cast<const Stmt *>(E), AC);
}

bool SAGenTestChecker::isCallNamed(const CallExpr *CE, StringRef Name) {
  if (!CE) return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD) return false;
  if (const IdentifierInfo *II = FD->getIdentifier())
    return II->getName() == Name;
  return false;
}

bool SAGenTestChecker::stmtContainsText(const Stmt *S, StringRef Sub, ASTContext &AC) {
  if (!S) return false;
  std::string Txt = getNodeText(S, AC);
  return StringRef(Txt).contains(Sub);
}

bool SAGenTestChecker::memberExprHasField(const MemberExpr *ME, StringRef FieldName) {
  if (!ME) return false;
  return ME->getMemberNameInfo().getAsString() == FieldName;
}

const MemberExpr *SAGenTestChecker::findMemberExprWithField(const Stmt *S,
                                                            ArrayRef<StringRef> FieldNames) {
  if (!S) return nullptr;

  // Simple recursive walk
  if (const auto *ME = dyn_cast<MemberExpr>(S)) {
    for (auto FN : FieldNames) {
      if (memberExprHasField(ME, FN))
        return ME;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (const MemberExpr *Found = findMemberExprWithField(Child, FieldNames))
      return Found;
  }
  return nullptr;
}

const CallExpr *SAGenTestChecker::findCallInStmtByName(const Stmt *S, StringRef Name) {
  if (!S) return nullptr;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (isCallNamed(CE, Name))
      return CE;
  }

  for (const Stmt *Child : S->children()) {
    if (const CallExpr *Found = findCallInStmtByName(Child, Name))
      return Found;
  }
  return nullptr;
}

void SAGenTestChecker::collectAllCalls(const Stmt *S, llvm::SmallVectorImpl<const CallExpr*> &Out) {
  if (!S) return;
  if (const auto *CE = dyn_cast<CallExpr>(S))
    Out.push_back(CE);
  for (const Stmt *Child : S->children())
    collectAllCalls(Child, Out);
}

bool SAGenTestChecker::stmtHasSpinLockAcquireOnTxLock(const Stmt *S, StringRef BaseText, ASTContext &AC) {
  if (!S) return false;

  // First, source-text based guard(...) detection.
  if (!BaseText.empty()) {
    if (stmtContainsText(S, "guard(", AC) &&
        stmtContainsText(S, "->tx_lock", AC) &&
        stmtContainsText(S, BaseText, AC)) {
      return true;
    }
  }

  // Then, look for known spin_lock calls and verify first argument targets base->tx_lock.
  llvm::SmallVector<const CallExpr*, 8> Calls;
  collectAllCalls(S, Calls);

  for (const CallExpr *CE : Calls) {
    if (!CE) continue;
    if (!(isCallNamed(CE, "spin_lock") ||
          isCallNamed(CE, "spin_lock_irqsave") ||
          isCallNamed(CE, "spin_lock_bh")))
      continue;

    if (CE->getNumArgs() == 0)
      continue;

    const Expr *Arg0 = CE->getArg(0);
    if (!Arg0) continue;

    std::string ArgText = getNodeText(Arg0, AC);
    // Require both the base text and ->tx_lock to be present to reduce false positives.
    if (!BaseText.empty() &&
        StringRef(ArgText).contains(BaseText) &&
        StringRef(ArgText).contains("->tx_lock")) {
      return true;
    }
  }

  return false;
}

const CompoundStmt *SAGenTestChecker::findNearestCompoundAncestor(ASTContext &AC, const Stmt *S) {
  if (!S) return nullptr;
  const Stmt *Cur = S;
  while (Cur) {
    auto Parents = AC.getParents(*Cur);
    if (Parents.empty())
      return nullptr;
    const DynTypedNode &DN = Parents[0];
    if (const auto *CS = DN.get<CompoundStmt>())
      return CS;
    if (const Stmt *P = DN.get<Stmt>()) {
      Cur = P;
      continue;
    }
    // Hit a non-statement parent (e.g., Decl), stop.
    break;
  }
  return nullptr;
}

bool SAGenTestChecker::compoundHasPrecedingLock(const CompoundStmt *CS, const Stmt *Child,
                                                StringRef BaseText, ASTContext &AC) {
  if (!CS || !Child) return false;

  // Find Child index in CS body
  unsigned Idx = 0;
  bool Found = false;
  for (const Stmt *S : CS->body()) {
    if (S == Child) { Found = true; break; }
    ++Idx;
  }
  if (!Found) return false;

  // Scan statements before the child
  unsigned Cur = 0;
  for (const Stmt *S : CS->body()) {
    if (Cur++ >= Idx) break;
    if (stmtHasSpinLockAcquireOnTxLock(S, BaseText, AC))
      return true;
  }
  return false;
}

bool SAGenTestChecker::loopOrContextHasTxLock(const ForStmt *FS, const Expr *Base, ASTContext &AC) {
  if (!FS) return false;

  std::string BaseText = Base ? getNodeText(Base, AC) : std::string();

  // 1) Search inside loop body
  if (const Stmt *Body = FS->getBody()) {
    if (stmtHasSpinLockAcquireOnTxLock(Body, BaseText, AC))
      return true;
  }

  // 2) Search preceding statements in the nearest compound ancestor
  const CompoundStmt *CS = findNearestCompoundAncestor(AC, FS);
  if (compoundHasPrecedingLock(CS, FS, BaseText, AC))
    return true;

  return false;
}

void SAGenTestChecker::analyzeForStmt(const ForStmt *FS, const Decl *D,
                                      AnalysisManager &Mgr, BugReporter &BR) const {
  if (!FS) return;

  ASTContext &AC = Mgr.getASTContext();

  // Check whether this loop touches gsm->tx_ctrl_list or gsm->tx_data_list
  const MemberExpr *MEList =
      findMemberExprWithField(FS,
        {StringRef("tx_ctrl_list"), StringRef("tx_data_list")});
  if (!MEList)
    return;

  const Expr *Base = MEList->getBase();
  if (!Base)
    return;
  Base = Base->IgnoreParenImpCasts();

  // Verify that this loop frees entries (i.e., calls kfree inside the body)
  const Stmt *Body = FS->getBody();
  if (!Body)
    return;

  const CallExpr *KFreeCall = findCallInStmtByName(Body, "kfree");
  if (!KFreeCall)
    return;

  // Optional tightening: ensure this looks like a list_for_each_entry* macro loop
  // (do not require this strictly to avoid missing the target bug)
  bool LooksLikeLinuxList = stmtContainsText(FS, "list_for_each_entry", AC) ||
                            stmtContainsText(FS, "list_for_each_entry_safe", AC);
  // Not strictly required, so we won't return if false.

  // Check whether protecting tx_lock is held in this context
  if (!loopOrContextHasTxLock(FS, Base, AC)) {
    // Report bug
    PathDiagnosticLocation Loc;
    if (KFreeCall) {
      Loc = PathDiagnosticLocation::createBegin(KFreeCall, Mgr.getSourceManager(),
                                                Mgr.getAnalysisDeclContext(D));
    } else {
      Loc = PathDiagnosticLocation::createBegin(FS, Mgr.getSourceManager(),
                                                Mgr.getAnalysisDeclContext(D));
    }

    auto R = std::make_unique<BasicBugReport>(
        *BT,
        "Freeing gsm tx_* list without holding tx_lock; may cause use-after-free",
        Loc);
    if (KFreeCall)
      R->addRange(KFreeCall->getSourceRange());
    BR.emitReport(std::move(R));
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  if (!FD->hasBody())
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // Traverse to find ForStmt nodes
  struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
    const SAGenTestChecker *Checker;
    const Decl *D;
    AnalysisManager &Mgr;
    BugReporter &BR;
    LocalVisitor(const SAGenTestChecker *C, const Decl *D, AnalysisManager &Mgr, BugReporter &BR)
        : Checker(C), D(D), Mgr(Mgr), BR(BR) {}

    bool VisitForStmt(ForStmt *FS) {
      Checker->analyzeForStmt(FS, D, Mgr, BR);
      return true;
    }
  };

  LocalVisitor V(this, D, Mgr, BR);
  V.TraverseStmt(const_cast<Stmt*>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing of gsm tx_ctrl_list/tx_data_list entries without holding tx_lock",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
