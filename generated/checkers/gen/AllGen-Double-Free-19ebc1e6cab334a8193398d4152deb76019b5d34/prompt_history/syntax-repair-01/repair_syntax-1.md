## Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

## Instruction

The following checker fails to compile, and your task is to resolve the compilation error based on the provided error messages.

Here are some potential ways to fix the issue:

1. Use the correct API: The current API may not exist, or the class has no such member. Replace it with an appropriate one.

2. Use correct arguments: Ensure the arguments passed to the API have the correct types and the correct number.

3. Change the variable types: Adjust the types of some variables based on the error messages.

4. Be careful if you want to include a header file. Please make sure the header file exists. For instance "fatal error: clang/StaticAnalyzer/Core/PathDiagnostic.h: No such file or directory".

**The version of Clang environment is Clang-18. You should consider the API compatibility.**

**Please only repair the failed parts and keep the original semantics.**
**Please return the whole checker code after fixing the compilation error.**

## Suggestions

1. Please only use two types of bug reports:
  - BasicBugReport (const BugType &bt, StringRef desc, PathDiagnosticLocation l)
  - PathSensitiveBugReport (const BugType &bt, StringRef desc, const ExplodedNode *errorNode)
  - PathSensitiveBugReport (const BugType &bt, StringRef shortDesc, StringRef desc, const ExplodedNode *errorNode)

## Example

- Error Line: 48 |   Optional<DefinedOrUnknownSVal> SizeSVal;

  - Error Messages: ‘Optional’ was not declared in this scope; did you mean ‘clang::ObjCImplementationControl::Optional’?

  - Fix: Replace 'Optional<DefinedOrUnknownSVal>' with 'std::optional<DefinedOrUnknownSVal>', and include the appropriate header.

- Error Line: 113 |     const MemRegion *MR = Entry.first;

    - Error Messages: unused variable ‘MR’ [-Wunused-variable]

    - Fix: Remove the variable 'MR' if it is not used.

## Checker

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
#include "clang/AST/StmtVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include <map>
#include <set>
#include <vector>
#include <string>
#include <algorithm>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free on retry path", "Memory Management")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      struct LabelInfo {
        const LabelDecl *LD = nullptr;
        std::string Name;
        SourceLocation Loc;
        const LabelStmt *LS = nullptr;
      };

      struct GotoInfo {
        const GotoStmt *GS = nullptr;
        const LabelDecl *Target = nullptr;
        SourceLocation FromLoc;
      };

      struct FreeInfo {
        const CallExpr *CE = nullptr;
        const VarDecl *VD = nullptr;
        SourceLocation Loc;
        const LabelDecl *CleanupLabel = nullptr; // Dominating label immediately preceding this free site
      };

      struct ResetInfo {
        const VarDecl *VD = nullptr;
        SourceLocation Loc;
        const Stmt *S = nullptr;
      };

      struct AllocInfo {
        const VarDecl *VD = nullptr;
        SourceLocation Loc;
        const CallExpr *CE = nullptr;
      };

      class BodyScanner : public RecursiveASTVisitor<BodyScanner> {
      public:
        BodyScanner(ASTContext &AC, const SourceManager &SM)
            : Ctx(AC), SM(SM) {}

        // Collections:
        std::vector<LabelInfo> Labels;
        std::map<const LabelDecl *, LabelInfo> LabelMap;
        std::vector<GotoInfo> Gotos;
        std::vector<FreeInfo> Frees;
        std::map<const LabelDecl *, std::vector<const VarDecl *>> CleanupFrees; // per cleanup label which vars are freed
        std::map<const VarDecl *, std::vector<ResetInfo>> Resets;
        std::map<const VarDecl *, std::vector<AllocInfo>> Allocs;

        // Accessor helpers
        static bool isFreeLike(const FunctionDecl *FD) {
          if (!FD) return false;
          if (const IdentifierInfo *II = FD->getIdentifier()) {
            StringRef N = II->getName();
            return N == "kfree" || N == "kvfree" || N == "vfree";
          }
          return false;
        }

        static bool isAllocLike(const FunctionDecl *FD) {
          if (!FD) return false;
          if (const IdentifierInfo *II = FD->getIdentifier()) {
            StringRef N = II->getName();
            return N == "kmalloc" || N == "kzalloc" || N == "kcalloc" ||
                   N == "kmalloc_array" || N == "kvmalloc" || N == "kvzalloc" ||
                   N == "vmalloc";
          }
          return false;
        }

        bool isNullExpr(const Expr *E) const {
          if (!E) return false;
          E = E->IgnoreParenImpCasts();
          if (E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull))
            return true;
          if (isa<GNUNullExpr>(E))
            return true;
          if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
            return IL->getValue() == 0;
          }
          // Fallback: textual check for NULL macro
          CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
          StringRef Text = Lexer::getSourceText(Range, SM, Ctx.getLangOpts());
          if (Text.contains("NULL"))
            return true;
          return false;
        }

        bool VisitStmt(Stmt *S) {
          if (!S) return true;

          if (auto *LS = dyn_cast<LabelStmt>(S)) {
            LabelInfo LI;
            LI.LD = LS->getDecl();
            if (LI.LD) LI.Name = LI.LD->getNameAsString();
            LI.Loc = LS->getBeginLoc();
            LI.LS = LS;
            Labels.push_back(LI);
            if (LI.LD)
              LabelMap[LI.LD] = LI;
          } else if (auto *GS = dyn_cast<GotoStmt>(S)) {
            GotoInfo GI;
            GI.GS = GS;
            GI.Target = GS->getLabel();
            GI.FromLoc = GS->getGotoLoc();
            Gotos.push_back(GI);
          } else if (auto *BO = dyn_cast<BinaryOperator>(S)) {
            if (BO->getOpcode() == BO_Assign) {
              const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
              const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
              const DeclRefExpr *LDRE = dyn_cast<DeclRefExpr>(LHS);
              const VarDecl *VD = LDRE ? dyn_cast<VarDecl>(LDRE->getDecl()) : nullptr;

              if (VD && VD->hasLocalStorage() && VD->getType()->isPointerType()) {
                // Null reset detection
                if (isNullExpr(RHS)) {
                  ResetInfo RI;
                  RI.VD = VD;
                  RI.Loc = BO->getExprLoc();
                  RI.S = BO;
                  Resets[VD].push_back(RI);
                } else if (const CallExpr *RCE = dyn_cast<CallExpr>(RHS)) {
                  const FunctionDecl *FD = RCE->getDirectCallee();
                  if (isAllocLike(FD)) {
                    AllocInfo AI;
                    AI.VD = VD;
                    AI.Loc = BO->getExprLoc();
                    AI.CE = RCE;
                    Allocs[VD].push_back(AI);
                  }
                }
              }
            }
          } else if (auto *DS = dyn_cast<DeclStmt>(S)) {
            for (auto *D : DS->decls()) {
              if (auto *VD = dyn_cast<VarDecl>(D)) {
                if (!VD->hasLocalStorage() || !VD->getType()->isPointerType())
                  continue;
                if (const Expr *Init = VD->getInit()) {
                  Init = Init->IgnoreParenImpCasts();
                  if (isNullExpr(Init)) {
                    ResetInfo RI;
                    RI.VD = VD;
                    RI.Loc = DS->getBeginLoc();
                    RI.S = DS;
                    Resets[VD].push_back(RI);
                  } else if (const CallExpr *CE = dyn_cast<CallExpr>(Init)) {
                    const FunctionDecl *FD = CE->getDirectCallee();
                    if (isAllocLike(FD)) {
                      AllocInfo AI;
                      AI.VD = VD;
                      AI.Loc = DS->getBeginLoc();
                      AI.CE = CE;
                      Allocs[VD].push_back(AI);
                    }
                  }
                }
              }
            }
          } else if (auto *CE = dyn_cast<CallExpr>(S)) {
            const FunctionDecl *FD = CE->getDirectCallee();
            if (isFreeLike(FD)) {
              // First arg is the freed pointer
              if (CE->getNumArgs() >= 1) {
                const Expr *Arg0 = CE->getArg(0);
                Arg0 = Arg0 ? Arg0->IgnoreParenImpCasts() : nullptr;
                const DeclRefExpr *DRE = Arg0 ? dyn_cast<DeclRefExpr>(Arg0) : nullptr;
                const VarDecl *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
                if (VD && VD->hasLocalStorage() && VD->getType()->isPointerType()) {
                  FreeInfo FI;
                  FI.CE = CE;
                  FI.VD = VD;
                  FI.Loc = CE->getExprLoc();
                  // Associate with the closest preceding label (cleanup)
                  const LabelDecl *DomLabel = findDominatingLabel(FI.Loc);
                  FI.CleanupLabel = DomLabel;
                  Frees.push_back(FI);
                  if (DomLabel)
                    CleanupFrees[DomLabel].push_back(VD);
                }
              }
            }
          }
          return true;
        }

        const LabelDecl *findDominatingLabel(SourceLocation Loc) const {
          // Find label with largest location that is before Loc.
          const LabelDecl *Best = nullptr;
          SourceLocation BestLoc;
          for (const auto &LI : Labels) {
            SourceLocation L = LI.Loc;
            if (SM.isBeforeInTranslationUnit(L, Loc)) {
              if (!Best ||
                  SM.isBeforeInTranslationUnit(BestLoc, L)) {
                Best = LI.LD;
                BestLoc = L;
              }
            }
          }
          return Best;
        }

      private:
        ASTContext &Ctx;
        const SourceManager &SM;
      }; // BodyScanner

      // Helper comparisons on source locations
      static bool isBefore(const SourceManager &SM, SourceLocation A, SourceLocation B) {
        return SM.isBeforeInTranslationUnit(A, B);
      }
      static bool isAfter(const SourceManager &SM, SourceLocation A, SourceLocation B) {
        return SM.isBeforeInTranslationUnit(B, A);
      }
      static bool isAfterOrEqual(const SourceManager &SM, SourceLocation A, SourceLocation B) {
        return !SM.isBeforeInTranslationUnit(A, B);
      }

      static SourceLocation getFunctionEndLoc(const Decl *D) {
        if (const auto *FD = dyn_cast<FunctionDecl>(D)) {
          if (const Stmt *Body = FD->getBody())
            return Body->getEndLoc();
        }
        return D->getEndLoc();
      }
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  const SourceManager &SM = Mgr.getSourceManager();
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  BodyScanner Scanner(Ctx, SM);
  Scanner.TraverseStmt(const_cast<Stmt *>(Body));

  if (Scanner.Labels.empty() || Scanner.Gotos.empty() || Scanner.Frees.empty())
    return;

  // Build set of replay labels: labels that are targets of a backward goto
  std::set<const LabelDecl *> ReplayLabels;
  for (const auto &GI : Scanner.Gotos) {
    const LabelDecl *T = GI.Target;
    if (!T) continue;
    auto It = Scanner.LabelMap.find(T);
    if (It == Scanner.LabelMap.end()) continue;
    SourceLocation LabelLoc = It->second.Loc;
    if (isBefore(SM, LabelLoc, GI.FromLoc)) {
      ReplayLabels.insert(T);
    }
  }

  if (ReplayLabels.empty())
    return;

  // For convenience build map of free infos per cleanup label
  std::map<const LabelDecl *, std::vector<FreeInfo>> FreeInfosPerCleanup;
  for (const auto &FI : Scanner.Frees) {
    if (!FI.CleanupLabel) continue;
    FreeInfosPerCleanup[FI.CleanupLabel].push_back(FI);
  }

  SourceLocation FuncEndLoc = getFunctionEndLoc(D);

  // For each replay label and cleanup label with frees, check the unsafe window
  for (const LabelDecl *La : ReplayLabels) {
    auto LaIt = Scanner.LabelMap.find(La);
    if (LaIt == Scanner.LabelMap.end())
      continue;
    SourceLocation LocA = LaIt->second.Loc;

    for (const auto &LbEntry : FreeInfosPerCleanup) {
      const LabelDecl *Lb = LbEntry.first;
      const auto &FIVec = LbEntry.second;

      // For each freed variable at this cleanup label
      for (const FreeInfo &FI : FIVec) {
        const VarDecl *V = FI.VD;
        if (!V) continue;

        // 1) There must exist a goto to La that occurs after this free location.
        const GotoStmt *AnchorGoto = nullptr;
        for (const auto &GI : Scanner.Gotos) {
          if (GI.Target == La && isAfter(SM, GI.FromLoc, FI.Loc)) {
            AnchorGoto = GI.GS;
            break;
          }
        }
        if (!AnchorGoto)
          continue;

        // 2) Find earliest allocation for V after La (replay header)
        SourceLocation LocAlloc = FuncEndLoc;
        bool FoundAlloc = false;
        auto AIIt = Scanner.Allocs.find(V);
        if (AIIt != Scanner.Allocs.end()) {
          for (const auto &AI : AIIt->second) {
            if (isAfter(SM, AI.Loc, LocA)) {
              if (!FoundAlloc || isBefore(SM, AI.Loc, LocAlloc)) {
                LocAlloc = AI.Loc;
                FoundAlloc = true;
              }
            }
          }
        }

        // 3) Check if there exists a reset to NULL for V between [LocA, LocAlloc)
        bool HasReset = false;
        auto RIIt = Scanner.Resets.find(V);
        if (RIIt != Scanner.Resets.end()) {
          for (const auto &RI : RIIt->second) {
            if (isAfterOrEqual(SM, RI.Loc, LocA) && isBefore(SM, RI.Loc, LocAlloc)) {
              HasReset = true;
              break;
            }
          }
        }
        if (HasReset)
          continue; // safe, reset to NULL after replay label

        // 4) Check if there exists any goto to cleanup label Lb in [LocA, LocAlloc)
        bool HasEarlyGotoToCleanup = false;
        for (const auto &GI : Scanner.Gotos) {
          if (GI.Target == Lb &&
              isAfterOrEqual(SM, GI.FromLoc, LocA) &&
              isBefore(SM, GI.FromLoc, LocAlloc)) {
            HasEarlyGotoToCleanup = true;
            break;
          }
        }
        if (!HasEarlyGotoToCleanup)
          continue;

        // Report bug
        if (!BT)
          return;

        std::string Msg = "Pointer freed in cleanup but not reset before retry; possible double free on replay path";
        auto R = std::make_unique<BasicBugReport>(*BT, Msg, AnchorGoto->getSourceRange().getBegin());
        R->addRange(AnchorGoto->getSourceRange());
        if (const IdentifierInfo *II = V->getIdentifier()) {
          R->addNote("Freed pointer: " + II->getName().str(), FI.Loc);
        } else {
          R->addNote("Freed pointer", FI.Loc);
        }
        BR.emitReport(std::move(R));
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free risk in replay loops when a freed pointer is not reset to NULL before retry",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 388 |           R->addNote("Freed pointer: " + II->getName().str(), FI.Loc);

	- Error Messages: cannot convert ‘const clang::SourceLocation’ to ‘const clang::ento::PathDiagnosticLocation&’

- Error Line: 390 |           R->addNote("Freed pointer", FI.Loc);

	- Error Messages: cannot convert ‘const clang::SourceLocation’ to ‘const clang::ento::PathDiagnosticLocation&’

- Error Line: 962 |     { return unique_ptr<_Tp>(new _Tp(std::forward<_Args>(__args)...)); }

	- Error Messages: no matching function for call to ‘clang::ento::BasicBugReport::BasicBugReport(clang::ento::BugType&, std::__cxx11::basic_string<char>&, clang::SourceLocation)’



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
