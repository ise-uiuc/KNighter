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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Missing protecting spinlock when freeing list", "Concurrency")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helpers
  static bool isFreeLike(const CallEvent &Call, CheckerContext &C);
  static bool isSpinLockAcquireCE(const CallExpr *CE, CheckerContext &C);
  static void collectCallExprs(const Stmt *S, llvm::SmallVectorImpl<const CallExpr*> &Out);
  static const MemberExpr* findMemberExprWithSuffix(const Stmt *Root, StringRef Suffix);
  static std::string extractRootDeclName(const Expr *E);
  static const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C);
  static bool sameBaseObject(const Expr *A, const Expr *B, CheckerContext &C);
  static bool matchLockForList(const Expr *LockArg, const MemberExpr *ListME, StringRef BaseName, CheckerContext &C);
};

bool SAGenTestChecker::isFreeLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *Orig = Call.getOriginExpr();
  if (!Orig)
    return false;
  // Use ExprHasName for robust matching.
  if (ExprHasName(Orig, "kfree", C))
    return true;
  if (ExprHasName(Orig, "kvfree", C))
    return true;
  return false;
}

bool SAGenTestChecker::isSpinLockAcquireCE(const CallExpr *CE, CheckerContext &C) {
  if (!CE)
    return false;
  // Check for multiple known spinlock acquire APIs
  static const char *Names[] = {
    "spin_lock", "spin_lock_irqsave", "spin_lock_bh",
    "_raw_spin_lock", "_raw_spin_lock_irqsave",
    "raw_spin_lock", "raw_spin_lock_irqsave"
  };

  for (const char *N : Names) {
    if (ExprHasName(CE, N, C))
      return true;
  }
  return false;
}

void SAGenTestChecker::collectCallExprs(const Stmt *S, llvm::SmallVectorImpl<const CallExpr*> &Out) {
  if (!S)
    return;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    Out.push_back(CE);
  }
  for (const Stmt *Child : S->children()) {
    if (Child)
      collectCallExprs(Child, Out);
  }
}

static const FieldDecl* getFieldFromMemberExpr(const MemberExpr *ME) {
  if (!ME)
    return nullptr;
  if (const auto *FD = dyn_cast_or_null<FieldDecl>(ME->getMemberDecl()))
    return FD;
  return nullptr;
}

const MemberExpr* SAGenTestChecker::findMemberExprWithSuffix(const Stmt *Root, StringRef Suffix) {
  if (!Root)
    return nullptr;

  if (const auto *ME = dyn_cast<MemberExpr>(Root)) {
    if (const FieldDecl *FD = getFieldFromMemberExpr(ME)) {
      StringRef Name = FD->getName();
      if (Name.endswith(Suffix))
        return ME;
    }
  }

  for (const Stmt *Child : Root->children()) {
    if (const MemberExpr *Found = findMemberExprWithSuffix(Child, Suffix))
      return Found;
  }
  return nullptr;
}

std::string SAGenTestChecker::extractRootDeclName(const Expr *E) {
  if (!E)
    return {};
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const ValueDecl *VD = DRE->getDecl();
    if (VD)
      return VD->getNameAsString();
    return {};
  }
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    return extractRootDeclName(ME->getBase());
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    return extractRootDeclName(UO->getSubExpr());
  }
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    return extractRootDeclName(ASE->getBase());
  }
  return {};
}

const MemRegion* SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  // Always normalize to base region as suggested.
  MR = MR->getBaseRegion();
  return MR;
}

bool SAGenTestChecker::sameBaseObject(const Expr *A, const Expr *B, CheckerContext &C) {
  const MemRegion *RA = getBaseRegionFromExpr(A, C);
  const MemRegion *RB = getBaseRegionFromExpr(B, C);
  if (!RA || !RB)
    return false;
  return RA == RB;
}

bool SAGenTestChecker::matchLockForList(const Expr *LockArg, const MemberExpr *ListME, StringRef BaseName, CheckerContext &C) {
  if (!LockArg || !ListME)
    return false;

  // Precise match via region base equality
  if (sameBaseObject(LockArg, ListME->getBase(), C))
    return true;

  // Fallback textual check if regions not available or didn't match
  if (!BaseName.empty()) {
    if (ExprHasName(LockArg, BaseName, C) && ExprHasName(LockArg, "_lock", C))
      return true;
  }
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isFreeLike(Call, C))
    return;

  const Expr *CallExprE = Call.getOriginExpr();
  if (!CallExprE)
    return;

  // Ensure we are inside a for-loop (likely a list_for_each* expansion).
  const ForStmt *FS = findSpecificTypeInParents<ForStmt>(CallExprE, C);
  if (!FS)
    return;

  // Find a MemberExpr under this ForStmt that references a list head with suffix "_list".
  const MemberExpr *ListME = findMemberExprWithSuffix(FS, "_list");
  if (!ListME)
    return;

  // Extract a textual base name for fallback (e.g., "gsm" in gsm->tx_ctrl_list).
  std::string BaseName = extractRootDeclName(ListME->getBase());

  // Find the surrounding compound statement to scan preceding statements for spin_lock acquisition.
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(FS, C);
  if (!CS)
    return;

  // Iterate statements in CS and scan those before FS.
  bool FoundFS = false;
  bool FoundProtectingLock = false;

  for (const Stmt *S : CS->body()) {
    if (S == FS) {
      FoundFS = true;
      break;
    }

    // Scan calls within this preceding statement.
    llvm::SmallVector<const CallExpr*, 8> Calls;
    collectCallExprs(S, Calls);
    for (const CallExpr *CE : Calls) {
      if (!isSpinLockAcquireCE(CE, C))
        continue;

      // First argument should be the lock pointer (e.g., &gsm->tx_lock).
      if (CE->getNumArgs() < 1)
        continue;

      const Expr *Arg0 = CE->getArg(0);
      if (matchLockForList(Arg0, ListME, BaseName, C)) {
        FoundProtectingLock = true;
        break;
      }
    }
    if (FoundProtectingLock)
      break;
  }

  if (!FoundFS) {
    // FS wasn't within the body list; conservative bail.
    return;
  }

  if (!FoundProtectingLock) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Freeing list elements without holding the protecting spinlock", N);
    R->addRange(Call.getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing/iterating kernel list entries without holding the protecting spinlock",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
