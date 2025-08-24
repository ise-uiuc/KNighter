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
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   // Summary: function -> vector of (param index, field freed)
   struct FreedFieldEntry {
     unsigned ParamIndex = 0;
     const FieldDecl *Field = nullptr;
   };

   // Helper function summaries (persist across functions in the TU)
   mutable llvm::DenseMap<const FunctionDecl*, llvm::SmallVector<FreedFieldEntry, 4>> HelperSummary;
   mutable llvm::DenseSet<const FunctionDecl*> Summarized;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free of struct member via helper", "Memory Management")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Summarization utilities
      void summarizeHelper(const FunctionDecl *FD, ASTContext &Ctx) const;
      const llvm::SmallVector<FreedFieldEntry, 4> *getHelperSummary(const FunctionDecl *FD, ASTContext &Ctx) const;

      // Matching utilities
      static bool isKfreeLike(const CallExpr *CE);
      static bool extractFreedMemberFromArg(const Expr *Arg, const FieldDecl *&FDOut, const Expr *&BaseOut);
      static std::string getBaseIdentName(const Expr *E);

      // Reporting
      void reportDoubleFree(const CallExpr *ManualFreeCE, const CallExpr *HelperCallCE,
                            const FieldDecl *FD, const FunctionDecl *HelperFD,
                            BugReporter &BR, AnalysisDeclContext *ADC) const;

      // Visitors
      class HelperBodyVisitor;
      class FunctionBodyScanner;
};

class SAGenTestChecker::HelperBodyVisitor : public RecursiveASTVisitor<HelperBodyVisitor> {
  const FunctionDecl *FD;
  ASTContext &Ctx;
  llvm::SmallVector<FreedFieldEntry, 4> &Out;
public:
  HelperBodyVisitor(const FunctionDecl *FD, ASTContext &Ctx,
                    llvm::SmallVector<FreedFieldEntry, 4> &Out)
      : FD(FD), Ctx(Ctx), Out(Out) {}

  bool VisitCallExpr(CallExpr *CE) {
    if (!SAGenTestChecker::isKfreeLike(CE))
      return true;

    if (CE->getNumArgs() < 1)
      return true;

    const Expr *Arg = CE->getArg(0);
    const FieldDecl *FreedField = nullptr;
    const Expr *BaseExpr = nullptr;
    if (!SAGenTestChecker::extractFreedMemberFromArg(Arg, FreedField, BaseExpr))
      return true;

    if (!FreedField || !BaseExpr)
      return true;

    // Ensure base expr originates from a parameter of FD
    const Expr *Base = BaseExpr;
    while (true) {
      Base = Base->IgnoreParenImpCasts();
      if (const auto *UO = dyn_cast<UnaryOperator>(Base)) {
        if (UO->getOpcode() == UO_Deref || UO->getOpcode() == UO_AddrOf) {
          Base = UO->getSubExpr();
          continue;
        }
      }
      break;
    }

    const ParmVarDecl *PVD = nullptr;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
    }
    if (!PVD)
      return true;

    // Find param index
    unsigned Index = 0;
    bool Found = false;
    for (const ParmVarDecl *Param : FD->parameters()) {
      if (Param == PVD) {
        Found = true;
        break;
      }
      ++Index;
    }
    if (!Found)
      return true;

    // Avoid duplicates
    for (const auto &E : Out) {
      if (E.ParamIndex == Index && E.Field == FreedField)
        return true;
    }
    FreedFieldEntry Entry;
    Entry.ParamIndex = Index;
    Entry.Field = FreedField;
    Out.push_back(Entry);
    return true;
  }
};

class SAGenTestChecker::FunctionBodyScanner : public RecursiveASTVisitor<FunctionBodyScanner> {
  const FunctionDecl *CurFD;
  ASTContext &Ctx;
  BugReporter &BR;
  AnalysisDeclContext *ADC;
  SAGenTestChecker &Checker;

  struct FreedRecord {
    const FieldDecl *Field = nullptr;
    std::string BaseName;
    const CallExpr *Call = nullptr;
    SourceLocation Loc;
  };

  llvm::SmallVector<FreedRecord, 8> ManualFrees;
  llvm::SmallVector<FreedRecord, 8> HelperFrees;

public:
  FunctionBodyScanner(const FunctionDecl *FD, ASTContext &Ctx, BugReporter &BR,
                      AnalysisDeclContext *ADC, SAGenTestChecker &Checker)
      : CurFD(FD), Ctx(Ctx), BR(BR), ADC(ADC), Checker(Checker) {}

  bool VisitCallExpr(CallExpr *CE) {
    if (!CE)
      return true;

    // Manual kfree-like
    if (SAGenTestChecker::isKfreeLike(CE)) {
      if (CE->getNumArgs() >= 1) {
        const FieldDecl *FreedField = nullptr;
        const Expr *BaseExpr = nullptr;
        if (SAGenTestChecker::extractFreedMemberFromArg(CE->getArg(0), FreedField, BaseExpr) &&
            FreedField && BaseExpr) {
          FreedRecord R;
          R.Field = FreedField;
          R.BaseName = SAGenTestChecker::getBaseIdentName(BaseExpr);
          R.Call = CE;
          R.Loc = CE->getExprLoc();

          // Check if there was a helper earlier that also frees this field of same base
          for (const auto &HF : HelperFrees) {
            if (HF.Field == R.Field && !HF.BaseName.empty() && HF.BaseName == R.BaseName) {
              // Report: helper then manual
              const FunctionDecl *HelperFD = nullptr;
              if (const auto *Callee = HF.Call->getDirectCallee())
                HelperFD = Callee;
              Checker.reportDoubleFree(R.Call, HF.Call, R.Field, HelperFD, BR, ADC);
              break;
            }
          }

          ManualFrees.push_back(R);
        }
      }
      return true;
    }

    // Other function calls: see if helper with summary
    const FunctionDecl *CalleeFD = CE->getDirectCallee();
    if (!CalleeFD)
      return true;

    // Ensure summary exists (lazy)
    (void)Checker.getHelperSummary(CalleeFD, Ctx);
    const auto *Summary = Checker.getHelperSummary(CalleeFD, Ctx);
    if (!Summary || Summary->empty())
      return true;

    // For each freed field summary, match against prior manual frees
    for (const auto &Entry : *Summary) {
      if (Entry.ParamIndex >= CE->getNumArgs())
        continue;
      const Expr *ArgE = CE->getArg(Entry.ParamIndex);
      std::string ArgName = SAGenTestChecker::getBaseIdentName(ArgE);
      if (ArgName.empty())
        continue;

      // Check prior manual frees
      for (const auto &MF : ManualFrees) {
        if (MF.Field == Entry.Field && !MF.BaseName.empty() && MF.BaseName == ArgName) {
          // Report: manual then helper
          Checker.reportDoubleFree(MF.Call, CE, MF.Field, CalleeFD, BR, ADC);
          break;
        }
      }

      // Record helper freed info for possible later manual frees
      FreedRecord HR;
      HR.Field = Entry.Field;
      HR.BaseName = ArgName;
      HR.Call = CE;
      HR.Loc = CE->getExprLoc();
      HelperFrees.push_back(HR);
    }

    return true;
  }
};

void SAGenTestChecker::summarizeHelper(const FunctionDecl *FD, ASTContext &Ctx) const {
  if (!FD)
    return;

  const FunctionDecl *Canon = FD->getCanonicalDecl();
  if (Summarized.count(Canon))
    return;

  Summarized.insert(Canon);
  llvm::SmallVector<FreedFieldEntry, 4> V;

  const Stmt *Body = FD->getBody();
  if (!Body) {
    HelperSummary[Canon] = std::move(V);
    return;
  }

  HelperBodyVisitor Vst(FD, Ctx, V);
  const_cast<Stmt *>(Body)->dump(); // No-op in release; can be removed if undesired
  Vst.TraverseStmt(const_cast<Stmt*>(Body));
  HelperSummary[Canon] = std::move(V);
}

const llvm::SmallVector<SAGenTestChecker::FreedFieldEntry, 4> *
SAGenTestChecker::getHelperSummary(const FunctionDecl *FD, ASTContext &Ctx) const {
  if (!FD)
    return nullptr;
  const FunctionDecl *Canon = FD->getCanonicalDecl();
  if (!Summarized.count(Canon))
    summarizeHelper(Canon, Ctx);
  auto It = HelperSummary.find(Canon);
  if (It == HelperSummary.end())
    return nullptr;
  return &It->second;
}

bool SAGenTestChecker::isKfreeLike(const CallExpr *CE) {
  if (!CE)
    return false;
  const FunctionDecl *Callee = CE->getDirectCallee();
  if (!Callee)
    return false;
  const IdentifierInfo *II = Callee->getIdentifier();
  if (!II)
    return false;
  StringRef Name = II->getName();
  return Name == "kfree" || Name == "kvfree";
}

bool SAGenTestChecker::extractFreedMemberFromArg(const Expr *Arg, const FieldDecl *&FDOut, const Expr *&BaseOut) {
  FDOut = nullptr;
  BaseOut = nullptr;
  if (!Arg)
    return false;

  const Expr *E = Arg->IgnoreParenImpCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return false;

  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return false;

  FDOut = FD;
  BaseOut = ME->getBase();
  return (FDOut != nullptr && BaseOut != nullptr);
}

std::string SAGenTestChecker::getBaseIdentName(const Expr *E) {
  if (!E)
    return std::string();
  const Expr *Cur = E;
  while (true) {
    Cur = Cur->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
      if (UO->getOpcode() == UO_AddrOf || UO->getOpcode() == UO_Deref) {
        Cur = UO->getSubExpr();
        continue;
      }
    } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Cur)) {
      Cur = ASE->getBase();
      continue;
    } else if (const auto *ME = dyn_cast<MemberExpr>(Cur)) {
      Cur = ME->getBase();
      continue;
    }
    break;
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(Cur)) {
    if (const auto *VD = dyn_cast<ValueDecl>(DRE->getDecl()))
      return VD->getNameAsString();
  }
  return std::string();
}

void SAGenTestChecker::reportDoubleFree(const CallExpr *ManualFreeCE, const CallExpr *HelperCallCE,
                                        const FieldDecl *FD, const FunctionDecl *HelperFD,
                                        BugReporter &BR, AnalysisDeclContext *ADC) const {
  if (!ManualFreeCE || !HelperCallCE || !FD)
    return;

  std::string FieldName = FD->getNameAsString();
  std::string HelperName = HelperFD ? HelperFD->getNameAsString() : "helper";

  std::string Msg = "Double free of field '" + FieldName + "' via kfree() and '" + HelperName + "()'";

  const SourceManager &SM = BR.getSourceManager();
  PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(ManualFreeCE, SM, ADC);

  auto R = std::make_unique<BasicBugReport>(*BT, Msg, Loc);
  R->addRange(ManualFreeCE->getSourceRange());

  PathDiagnosticLocation HelperLoc = PathDiagnosticLocation::createBegin(HelperCallCE, SM, ADC);
  R->addNote("'" + HelperName + "()' also frees this field", HelperLoc);

  BR.emitReport(std::move(R));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  ASTContext &Ctx = Mgr.getASTContext();

  // Pre-summarize current function (in case it's used as helper elsewhere)
  summarizeHelper(FD, Ctx);

  // Scan body for pattern: manual kfree of member + helper that also frees it
  AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(const_cast<Decl*>(D));
  FunctionBodyScanner Scanner(FD, Ctx, BR, ADC, *const_cast<SAGenTestChecker*>(this));
  Scanner.TraverseDecl(const_cast<FunctionDecl*>(FD));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of struct member: manual kfree and helper also frees the same member",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
