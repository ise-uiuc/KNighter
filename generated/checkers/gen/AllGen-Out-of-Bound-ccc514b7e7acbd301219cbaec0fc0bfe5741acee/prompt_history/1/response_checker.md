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
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/APInt.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Array bounds", "Loop index may overflow smaller parallel array")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

private:
  // Core analysis of a ForStmt
  void analyzeForStmt(const ForStmt *FS, const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

  // Helpers
  static bool evalExprToInt(const Expr *E, ASTContext &ACtx, llvm::APSInt &Out);
  static const VarDecl* getInductionVarIfZeroInit(const ForStmt *FS, ASTContext &ACtx);
  static bool exprContainsVar(const Expr *E, const VarDecl *Var);
  static bool computeStrictUpperBound(const ForStmt *FS, const VarDecl *Var, ASTContext &ACtx, uint64_t &UpperBound);
  static bool getArrayDeclAndSize(const Expr *BaseE, ASTContext &ACtx, const NamedDecl *&ND, uint64_t &Size);
  void reportIssue(const Decl *D, BugReporter &BR, const ArraySubscriptExpr *ASE,
                   StringRef ArrName, uint64_t UpperBound, uint64_t ArraySize) const;

  // Visitor to collect arrays indexed by a given induction variable
  class CollectArrayUsesVisitor : public RecursiveASTVisitor<CollectArrayUsesVisitor> {
    const VarDecl *IVar;
    ASTContext &ACtx;
    llvm::DenseMap<const NamedDecl*, std::pair<uint64_t, const ArraySubscriptExpr*>> &OutMap;

  public:
    CollectArrayUsesVisitor(const VarDecl *V, ASTContext &Ctx,
        llvm::DenseMap<const NamedDecl*, std::pair<uint64_t, const ArraySubscriptExpr*>> &M)
        : IVar(V), ACtx(Ctx), OutMap(M) {}

    bool VisitArraySubscriptExpr(const ArraySubscriptExpr *ASE) {
      const Expr *Idx = ASE->getIdx();
      if (!Idx)
        return true;

      if (!SAGenTestChecker::exprContainsVar(Idx, IVar))
        return true;

      const Expr *BaseE = ASE->getBase();
      if (!BaseE)
        return true;
      BaseE = BaseE->IgnoreParenImpCasts();

      const NamedDecl *ND = nullptr;
      uint64_t Size = 0;
      if (!SAGenTestChecker::getArrayDeclAndSize(BaseE, ACtx, ND, Size))
        return true;

      if (!OutMap.count(ND)) {
        OutMap[ND] = std::make_pair(Size, ASE);
      }
      return true;
    }
  };
};

// Evaluate expression to integer using ASTContext (for AST-only checker)
bool SAGenTestChecker::evalExprToInt(const Expr *E, ASTContext &ACtx, llvm::APSInt &Out) {
  if (!E)
    return false;
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, ACtx)) {
    Out = R.Val.getInt();
    return true;
  }
  return false;
}

// Return induction variable if loop is of simple form with init: i = 0 or int i = 0;
const VarDecl* SAGenTestChecker::getInductionVarIfZeroInit(const ForStmt *FS, ASTContext &ACtx) {
  if (!FS)
    return nullptr;

  const Stmt *Init = FS->getInit();
  if (!Init)
    return nullptr;

  // Case: int i = 0;
  if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
    if (!DS->isSingleDecl())
      return nullptr;
    if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
      if (!VD->hasInit())
        return nullptr;
      const Expr *InitE = VD->getInit();
      if (!InitE)
        return nullptr;
      llvm::APSInt Val;
      if (evalExprToInt(InitE->IgnoreParenCasts(), ACtx, Val) && Val == 0)
        return VD;
    }
    return nullptr;
  }

  // Case: i = 0;
  if (const auto *BO = dyn_cast<BinaryOperator>(Init)) {
    if (BO->getOpcode() != BO_Assign)
      return nullptr;
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    if (!LHS || !RHS)
      return nullptr;

    const auto *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE)
      return nullptr;
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return nullptr;

    llvm::APSInt Val;
    if (evalExprToInt(RHS, ACtx, Val) && Val == 0)
      return VD;

    return nullptr;
  }

  return nullptr;
}

// Determine whether an expression references the given VarDecl
bool SAGenTestChecker::exprContainsVar(const Expr *E, const VarDecl *Var) {
  if (!E || !Var)
    return false;

  struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
    const VarDecl *V;
    bool Found = false;
    LocalVisitor(const VarDecl *Var) : V(Var) {}
    bool VisitDeclRefExpr(const DeclRefExpr *DRE) {
      if (DRE->getDecl()->getCanonicalDecl() == V->getCanonicalDecl()) {
        Found = true;
      }
      return !Found; // stop traversal if found
    }
  };

  LocalVisitor V(Var);
  V.TraverseStmt(const_cast<Expr*>(E));
  return V.Found;
}

// Compute strict upper bound on iterations using the condition.
// Supported ascending forms:
//   i < N        => UB = N
//   i <= N       => UB = N + 1
//   N > i        => UB = N
//   N >= i       => UB = N + 1
bool SAGenTestChecker::computeStrictUpperBound(const ForStmt *FS, const VarDecl *Var,
                                               ASTContext &ACtx, uint64_t &UpperBound) {
  if (!FS || !Var)
    return false;
  const Expr *CondE = dyn_cast_or_null<Expr>(FS->getCond());
  if (!CondE)
    return false;
  CondE = CondE->IgnoreParenCasts();

  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  if (!LHS || !RHS)
    return false;

  llvm::APSInt Val;
  // i < N or i <= N
  if (exprContainsVar(LHS, Var) && (Op == BO_LT || Op == BO_LE)) {
    if (!evalExprToInt(RHS, ACtx, Val))
      return false;
    UpperBound = Val.getLimitedValue();
    if (Op == BO_LE)
      UpperBound += 1;
    return true;
  }

  // N > i or N >= i
  if (exprContainsVar(RHS, Var) && (Op == BO_GT || Op == BO_GE)) {
    if (!evalExprToInt(LHS, ACtx, Val))
      return false;
    UpperBound = Val.getLimitedValue();
    if (Op == BO_GE)
      UpperBound += 1;
    return true;
  }

  return false;
}

// Get the base declared array (VarDecl or FieldDecl) and its constant size, if any
bool SAGenTestChecker::getArrayDeclAndSize(const Expr *BaseE, ASTContext &ACtx,
                                           const NamedDecl *&ND, uint64_t &Size) {
  ND = nullptr;
  Size = 0;

  // Direct variable array reference
  if (const auto *DRE = dyn_cast<DeclRefExpr>(BaseE)) {
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;
    const ConstantArrayType *CAT = ACtx.getAsConstantArrayType(VD->getType());
    if (!CAT)
      return false;
    ND = VD->getCanonicalDecl();
    Size = CAT->getSize().getLimitedValue();
    return true;
  }

  // Struct/union member array reference
  if (const auto *ME = dyn_cast<MemberExpr>(BaseE)) {
    const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD)
      return false;
    const ConstantArrayType *CAT = ACtx.getAsConstantArrayType(FD->getType());
    if (!CAT)
      return false;
    ND = FD->getCanonicalDecl();
    Size = CAT->getSize().getLimitedValue();
    return true;
  }

  // Otherwise (pointer, VLA, unknown), bail out.
  return false;
}

void SAGenTestChecker::reportIssue(const Decl *D, BugReporter &BR, const ArraySubscriptExpr *ASE,
                                   StringRef ArrName, uint64_t UpperBound, uint64_t ArraySize) const {
  if (!ASE)
    return;

  // Keep message short and clear.
  SmallString<128> Msg;
  llvm::raw_svector_ostream OS(Msg);
  OS << "Loop bound exceeds size of array '" << ArrName << "' (" << UpperBound
     << " > " << ArraySize << ")";

  PathDiagnosticLocation Loc =
      PathDiagnosticLocation::createBegin(ASE, BR.getSourceManager(), D->getASTContext());
  auto R = std::make_unique<BasicBugReport>(*BT, OS.str(), Loc);
  R->addRange(ASE->getSourceRange());
  BR.emitReport(std::move(R));
}

void SAGenTestChecker::analyzeForStmt(const ForStmt *FS, const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!FS)
    return;

  ASTContext &ACtx = D->getASTContext();

  // Step A: Find simple induction variable i with init 0
  const VarDecl *IVar = getInductionVarIfZeroInit(FS, ACtx);
  if (!IVar)
    return;

  // Step A: Compute strict upper bound (number of iterations)
  uint64_t UpperBound = 0;
  if (!computeStrictUpperBound(FS, IVar, ACtx, UpperBound))
    return;

  // Step B: Collect arrays indexed by IVar in the loop body.
  llvm::DenseMap<const NamedDecl*, std::pair<uint64_t, const ArraySubscriptExpr*>> Arrays;
  CollectArrayUsesVisitor Collector(IVar, ACtx, Arrays);
  if (const Stmt *Body = FS->getBody())
    Collector.TraverseStmt(const_cast<Stmt*>(Body));

  // Require at least two distinct arrays to reduce false positives (parallel arrays)
  if (Arrays.size() < 2)
    return;

  // Step C: For each array with known size, if UB > size, report.
  for (const auto &It : Arrays) {
    const NamedDecl *ND = It.first;
    uint64_t Size = It.second.first;
    const ArraySubscriptExpr *ASE = It.second.second;

    if (UpperBound > Size) {
      std::string ArrName;
      if (const auto *FD = dyn_cast<FieldDecl>(ND))
        ArrName = FD->getNameAsString();
      else if (const auto *VD = dyn_cast<VarDecl>(ND))
        ArrName = VD->getNameAsString();
      else
        ArrName = "array";

      reportIssue(D, BR, ASE, ArrName, UpperBound, Size);
    }
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  // Traverse the body to find ForStmt and analyze each
  struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
    const SAGenTestChecker *Checker;
    const Decl *TopDecl;
    AnalysisManager &Mgr;
    BugReporter &BR;
    LocalVisitor(const SAGenTestChecker *C, const Decl *D, AnalysisManager &M, BugReporter &B)
        : Checker(C), TopDecl(D), Mgr(M), BR(B) {}

    bool VisitForStmt(const ForStmt *FS) {
      Checker->analyzeForStmt(FS, TopDecl, Mgr, BR);
      return true;
    }
  };

  LocalVisitor V(this, D, Mgr, BR);
  if (const Stmt *Body = D->getBody())
    V.TraverseStmt(const_cast<Stmt*>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect loops indexing multiple arrays with a bound larger than one array's size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
