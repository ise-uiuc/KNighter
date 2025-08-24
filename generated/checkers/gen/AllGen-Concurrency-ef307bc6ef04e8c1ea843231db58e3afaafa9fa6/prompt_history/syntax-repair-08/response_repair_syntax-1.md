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
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/SmallVector.h"
#include <string>
#include <vector>
#include <set>
#include <map>
#include <utility>
#include <algorithm>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states

namespace {

struct ReaderFact {
  std::string LockText;
  std::string PtrText;
  const FunctionDecl *FD = nullptr;
  SourceLocation CheckLoc;
  SourceLocation UseLoc;
};

struct WriterFact {
  std::string PtrText;
  std::set<std::string> HeldLocks;
  const FunctionDecl *FD = nullptr;
  SourceLocation AssignLoc;
};

static std::string trimSpaces(std::string S) {
  auto isSpace = [](char c){ return c==' ' || c=='\t' || c=='\n' || c=='\r' || c=='\f' || c=='\v'; };
  size_t B = 0, E = S.size();
  while (B < E && isSpace(S[B])) ++B;
  while (E > B && isSpace(S[E-1])) --E;
  return S.substr(B, E-B);
}

static std::string stripOuterParens(std::string S) {
  S = trimSpaces(S);
  bool Changed = true;
  while (Changed && S.size() >= 2) {
    Changed = false;
    if (S.front() == '(' && S.back() == ')') {
      // naive balance check: ensure outermost parens match (best-effort)
      int balance = 0;
      bool ok = true;
      for (size_t i = 0; i < S.size(); ++i) {
        if (S[i] == '(') balance++;
        else if (S[i] == ')') {
          balance--;
          if (balance == 0 && i != S.size() - 1) { ok = false; break; }
          if (balance < 0) { ok = false; break; }
        }
      }
      if (ok && balance == 0) {
        S = trimSpaces(S.substr(1, S.size()-2));
        Changed = true;
      }
    }
  }
  return S;
}

static std::string removeAllSpaces(const std::string &S) {
  std::string R;
  R.reserve(S.size());
  for (char c : S) {
    if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\v')
      R.push_back(c);
  }
  return R;
}

static std::string normalizeLockText(const std::string &SIn) {
  std::string S = stripOuterParens(SIn);
  S = trimSpaces(S);
  // Remove leading '&' symbols and spaces
  while (!S.empty() && (S[0] == '&' || S[0] == ' ' || S[0] == '\t'))
    S.erase(S.begin());
  S = stripOuterParens(S);
  // Remove all spaces for lock names to be robust
  S = removeAllSpaces(S);
  return S;
}

static std::string normalizePtrText(const std::string &SIn) {
  std::string S = stripOuterParens(SIn);
  S = trimSpaces(S);
  // Do not remove '&' for pointer text
  S = stripOuterParens(S);
  // Remove redundant spaces inside to be more robust
  S = removeAllSpaces(S);
  return S;
}

static std::string getExprText(const Expr *E, ASTContext &Ctx) {
  if (!E) return std::string();
  const SourceManager &SM = Ctx.getSourceManager();
  const LangOptions &Lang = Ctx.getLangOpts();
  SourceRange R = E->getSourceRange();
  CharSourceRange CR = CharSourceRange::getTokenRange(R);
  StringRef SR = Lexer::getSourceText(CR, SM, Lang);
  return SR.str();
}

static bool isNullPtrExpr(const Expr *E, ASTContext &Ctx) {
  if (!E) return false;
  return E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
}

static bool isPointerTypeExpr(const Expr *E) {
  if (!E) return false;
  QualType QT = E->getType();
  return !QT.isNull() && QT->isPointerType();
}

static bool getLockNameFromCall(const CallExpr *CE, std::string &LockName, bool &IsLock) {
  IsLock = false;
  if (!CE) return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD) return false;
  StringRef Name = FD->getName();
  bool isLock = (Name == "spin_lock" || Name == "spin_lock_irqsave" || Name == "spin_lock_bh");
  bool isUnlock = (Name == "spin_unlock" || Name == "spin_unlock_irqrestore" || Name == "spin_unlock_bh");
  if (!isLock && !isUnlock)
    return false;

  if (CE->getNumArgs() < 1) return false;
  const Expr *Arg0 = CE->getArg(0);
  if (!Arg0) return false;
  ASTContext &Ctx = FD->getASTContext();
  std::string ArgText = getExprText(Arg0, Ctx);
  LockName = normalizeLockText(ArgText);
  IsLock = isLock;
  return true;
}

static bool isNullCheckOrTruthiness(const Expr *Cond, ASTContext &Ctx, std::string &PtrTextOut) {
  if (!Cond) return false;
  const Expr *E = Cond->IgnoreParenCasts();
  // if (!P)
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
      if (isPointerTypeExpr(Sub)) {
        PtrTextOut = normalizePtrText(getExprText(Sub, Ctx));
        return !PtrTextOut.empty();
      }
    }
  }
  // if (P == NULL) or (P != NULL) or (NULL == P)
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSNull = isNullPtrExpr(LHS, Ctx);
      bool RHSNull = isNullPtrExpr(RHS, Ctx);
      if (LHSNull ^ RHSNull) {
        const Expr *PtrE = LHSNull ? RHS : LHS;
        if (isPointerTypeExpr(PtrE)) {
          PtrTextOut = normalizePtrText(getExprText(PtrE, Ctx));
          return !PtrTextOut.empty();
        }
      }
    }
  }
  // if (P) where P is a pointer-typed expr
  if (isPointerTypeExpr(E)) {
    PtrTextOut = normalizePtrText(getExprText(E, Ctx));
    return !PtrTextOut.empty();
  }
  return false;
}

static bool exprTextContains(const Expr *E, StringRef Name, ASTContext &Ctx) {
  if (!E) return false;
  std::string T = removeAllSpaces(getExprText(E, Ctx));
  return StringRef(T).contains(Name);
}

class FuncBodyVisitor : public RecursiveASTVisitor<FuncBodyVisitor> {
public:
  FuncBodyVisitor(ASTContext &Ctx,
                  const FunctionDecl *FD,
                  std::vector<ReaderFact> &Readers,
                  std::vector<WriterFact> &Writers)
      : Ctx(Ctx), FD(FD), Readers(Readers), Writers(Writers),
        SM(Ctx.getSourceManager()) {}

  bool VisitCallExpr(CallExpr *CE) {
    std::string LockName;
    bool IsLock = false;
    if (getLockNameFromCall(CE, LockName, IsLock)) {
      if (IsLock) {
        if (!LockName.empty())
          LockStack.push_back(LockName);
      } else {
        // unlock
        if (!LockStack.empty())
          LockStack.pop_back();
      }
      return true;
    }

    // Under a lock? Check for pointer uses as call arguments
    if (!LockStack.empty()) {
      const std::string &TopLock = LockStack.back();
      auto It = CheckedByLock.find(TopLock);
      if (It != CheckedByLock.end()) {
        for (const auto &P : It->second) {
          const std::string &PtrText = P.first;
          SourceLocation CheckLoc = P.second;
          // For each argument, see if it contains PtrText
          bool Used = false;
          for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
            if (exprTextContains(CE->getArg(i), PtrText, Ctx)) {
              Used = true;
              break;
            }
          }
          if (Used) {
            // Ensure source order: use after check
            SourceLocation UseLoc = CE->getExprLoc();
            if (SM.isBeforeInTranslationUnit(CheckLoc, UseLoc)) {
              ReaderFact RF;
              RF.LockText = TopLock;
              RF.PtrText = PtrText;
              RF.FD = FD;
              RF.CheckLoc = CheckLoc;
              RF.UseLoc = UseLoc;
              Readers.push_back(RF);
            }
          }
        }
      }
    }
    return true;
  }

  bool VisitIfStmt(IfStmt *IS) {
    if (LockStack.empty())
      return true;

    const Expr *Cond = IS->getCond();
    std::string PtrText;
    if (isNullCheckOrTruthiness(Cond, Ctx, PtrText)) {
      const std::string &TopLock = LockStack.back();
      if (!PtrText.empty()) {
        CheckedByLock[TopLock].push_back({PtrText, IS->getIfLoc()});
      }
    }
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (LockStack.empty())
      return true;

    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr();
      const std::string &TopLock = LockStack.back();
      auto It = CheckedByLock.find(TopLock);
      if (It != CheckedByLock.end()) {
        for (const auto &P : It->second) {
          const std::string &PtrText = P.first;
          SourceLocation CheckLoc = P.second;
          if (exprTextContains(Sub, PtrText, Ctx)) {
            SourceLocation UseLoc = UO->getExprLoc();
            if (SM.isBeforeInTranslationUnit(CheckLoc, UseLoc)) {
              ReaderFact RF;
              RF.LockText = TopLock;
              RF.PtrText = PtrText;
              RF.FD = FD;
              RF.CheckLoc = CheckLoc;
              RF.UseLoc = UseLoc;
              Readers.push_back(RF);
            }
          }
        }
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO)
      return true;

    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      if (LHS && RHS && isPointerTypeExpr(LHS) && isNullPtrExpr(RHS, Ctx)) {
        std::string LText = normalizePtrText(getExprText(LHS, Ctx));
        if (!LText.empty()) {
          WriterFact WF;
          WF.PtrText = LText;
          WF.FD = FD;
          WF.AssignLoc = BO->getOperatorLoc();
          // Collect currently held locks
          for (const auto &L : LockStack)
            WF.HeldLocks.insert(L);
          Writers.push_back(WF);
        }
      }
    }
    return true;
  }

private:
  ASTContext &Ctx;
  const FunctionDecl *FD;
  std::vector<ReaderFact> &Readers;
  std::vector<WriterFact> &Writers;
  const SourceManager &SM;

  std::vector<std::string> LockStack;
  // For each lock, list of (PtrText, CheckLoc)
  std::map<std::string, std::vector<std::pair<std::string, SourceLocation>>> CheckedByLock;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody, check::EndAnalysis> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Inconsistent locking on a shared pointer", "Concurrency")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
      void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;

   private:
      // Collected cross-function facts
      mutable std::vector<ReaderFact> Readers;
      mutable std::vector<WriterFact> Writers;

      void report(const WriterFact &W, const ReaderFact &R, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) return;
  if (!FD->hasBody()) return;

  ASTContext &Ctx = Mgr.getASTContext();
  const Stmt *Body = FD->getBody();
  if (!Body) return;

  FuncBodyVisitor V(Ctx, FD, Readers, Writers);
  V.TraverseStmt(const_cast<Stmt *>(Body));
}

void SAGenTestChecker::report(const WriterFact &W, const ReaderFact &R, BugReporter &BR) const {
  // Create a BasicBugReport at the writer's assignment
  PathDiagnosticLocation ELoc(W.AssignLoc, BR.getSourceManager());
  auto Rpt = std::make_unique<BasicBugReport>(
      *BT,
      ("Clearing '" + R.PtrText + "' outside lock '" + R.LockText +
       "'; can race with NULL-checked use under lock.")
          .c_str(),
      ELoc);
  BR.emitReport(std::move(Rpt));
}

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
  // Match readers to writers
  // De-duplicate by (WriterLoc, LockText, PtrText)
  std::set<std::string> Emitted;

  const SourceManager &SM = BR.getSourceManager();
  for (const auto &R : Readers) {
    for (const auto &W : Writers) {
      if (R.PtrText == W.PtrText) {
        // If the writer is not holding the reader's lock
        if (W.HeldLocks.find(R.LockText) == W.HeldLocks.end()) {
          // Build key
          std::string Key = std::to_string(W.AssignLoc.getRawEncoding()) + "|" + R.LockText + "|" + R.PtrText;
          if (Emitted.insert(Key).second) {
            report(W, R, BR);
          }
        }
      }
    }
  }

  // Clear facts for next analysis (if any)
  Readers.clear();
  Writers.clear();
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects clearing a shared pointer outside the protecting spinlock when it is NULL-checked and used under that lock elsewhere",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
