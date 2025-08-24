Refinement Plan:
- Root cause: The checker treats array subscript expressions that come from macro expansions (like IF_ISSET) as plain array indexing, and uses the underlying storage array’s physical length (e.g., a bitmap word array with size 8) as the “capacity”. When the loop upper bound is the logical count (e.g., MAXMIFS = 32), this looks like UB > Cap and triggers a report, even though the macro actually performs bit arithmetic and is safe. This is a classic AST-only false positive caused by macro-expanded bitset helpers.
- Fix: Add a targeted false-positive filter for macro-originated array subscripts. If an ArraySubscriptExpr or its base/index originate in a macro expansion, skip it. This eliminates the reported false positive in ip6mr.c while preserving detection for the AMD DML2 bug pattern (which occurs in normal code, not macro expansions).
- Additional considerations:
  - Keep the checker strict in matching direct indices arr[i], which is consistent with the target buggy pattern.
  - Maintain existing guard recognition (if (i < Cap) { ... } or prior if (i >= Cap) break/return/continue) to minimize other false positives.
  - No change in includes; ensure Clang-18 compatibility by using stable APIs (SourceLocation::isMacroID, ParentMapContext).
  - Edge cases: This change may skip macro-originated true positives, but those are rare for this specific pattern and acceptable to eliminate this concrete false positive without regressing the AMD detection.

Refined Code:
```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ParentMapContext.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Forward declarations of helpers
static bool evalInt(const ASTContext &Ctx, const Expr *E, llvm::APSInt &Res);
static bool containsDeclRefToVar(const Expr *E, const VarDecl *V);
static bool indexIsDirectLoopVar(const Expr *Idx, const VarDecl *IVar);
static bool getArrayConstSizeFromBase(const ASTContext &Ctx, const Expr *Base, uint64_t &CapOut);
static bool stmtContains(const Stmt *Root, const Stmt *Target);
static bool parseGuardCondition(const ASTContext &Ctx, const Expr *Cond, const VarDecl *IVar,
                                uint64_t Cap, bool &IsLTorLE, bool &IsGEorGT);
static bool isGuardedByEnclosingIfLtCap(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                        const VarDecl *IVar, uint64_t Cap);
static bool isGuardedByPrevIfGeBreak(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                     const VarDecl *IVar, uint64_t Cap);
static bool isGuardedBeforeUse(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                               const VarDecl *IVar, uint64_t Cap);

// New helpers to eliminate macro-originated false positives
static bool isFromMacro(const SourceRange &SR) {
  if (SR.isInvalid())
    return false;
  SourceLocation B = SR.getBegin();
  SourceLocation E = SR.getEnd();
  return (B.isMacroID() || E.isMacroID());
}

static bool isFromMacro(const Expr *E) {
  if (!E) return false;
  return isFromMacro(E->getSourceRange()) || E->getExprLoc().isMacroID();
}

// A single place to decide whether this ASE is a known false positive.
// Currently filters macro-originated subscripts, which covers the reported case
// (e.g., IF_ISSET-style bitset helpers).
static bool isFalsePositive(const ArraySubscriptExpr *ASE) {
  if (!ASE) return false;
  // If either the subscript expression itself, its base, or its index come from
  // a macro expansion, skip. Macros often hide bitset/packing tricks that the
  // AST-only checker cannot reason about safely.
  if (isFromMacro(ASE) || isFromMacro(ASE->getBase()) || isFromMacro(ASE->getIdx()))
    return true;
  return false;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
    : BT(std::make_unique<BugType>(this, "Loop bound exceeds array capacity", "Memory Error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

private:
  // Extract loop index variable and bounds from a ForStmt.
  // Returns true on success and sets IVar, LB, UBExclusive.
  static bool getLoopIndexAndBounds(const ForStmt *FS, const ASTContext &Ctx,
                                    const VarDecl *&IVar, llvm::APSInt &LB,
                                    llvm::APSInt &UBExclusive);

  // Process a single ForStmt: find array subscripts using IVar and check against Cap.
  void processForStmt(const ForStmt *FS, const ASTContext &Ctx, BugReporter &BR) const;

  // Emit a report for a problematic array access.
  void reportIssue(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                   uint64_t UBExclusive, uint64_t Cap,
                   BugReporter &BR, const ASTContext &Ctx) const;
};

//====================== Helper implementations ======================

static bool evalInt(const ASTContext &Ctx, const Expr *E, llvm::APSInt &Res) {
  if (!E) return false;
  Expr::EvalResult ER;
  if (E->EvaluateAsInt(ER, const_cast<ASTContext &>(Ctx))) {
    Res = ER.Val.getInt();
    return true;
  }
  return false;
}

static bool containsDeclRefToVar(const Expr *E, const VarDecl *V) {
  if (!E || !V) return false;
  struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
    const VarDecl *Var;
    bool Found;
    LocalVisitor(const VarDecl *V) : Var(V), Found(false) {}
    bool VisitDeclRefExpr(const DeclRefExpr *DRE) {
      if (DRE->getDecl() == Var) {
        Found = true;
        return false;
      }
      return true;
    }
  };
  LocalVisitor Vst(V);
  Vst.TraverseStmt(const_cast<Expr*>(E));
  return Vst.Found;
}

// Strict filter: Only accept index expressions that are directly the loop variable.
static bool indexIsDirectLoopVar(const Expr *Idx, const VarDecl *IVar) {
  if (!Idx || !IVar)
    return false;
  const Expr *E = Idx->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl() == IVar;

  // Allow trivial unary plus on the variable (rare in C, but harmless).
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Plus) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *SDRE = dyn_cast<DeclRefExpr>(Sub))
        return SDRE->getDecl() == IVar;
    }
  }

  // Do not accept composite/mapped indices like arr[map[i].field] or arr[i + k].
  return false;
}

static bool getArrayConstSizeFromBase(const ASTContext &Ctx, const Expr *Base, uint64_t &CapOut) {
  if (!Base) return false;
  const Expr *E = Base->IgnoreParenImpCasts();

  auto ExtractFromQT = [&](QualType QT) -> bool {
    if (QT.isNull()) return false;
    if (const auto *CAT = Ctx.getAsConstantArrayType(QT)) {
      CapOut = CAT->getSize().getLimitedValue();
      return true;
    }
    return false;
  };

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      return ExtractFromQT(VD->getType());
    }
  } else if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const auto *VD = dyn_cast<ValueDecl>(ME->getMemberDecl())) {
      return ExtractFromQT(VD->getType());
    }
  }
  return false;
}

static bool stmtContains(const Stmt *Root, const Stmt *Target) {
  if (!Root || !Target) return false;
  if (Root == Target) return true;
  for (const Stmt *Child : Root->children()) {
    if (Child && stmtContains(Child, Target))
      return true;
  }
  return false;
}

static bool parseGuardCondition(const ASTContext &Ctx, const Expr *Cond, const VarDecl *IVar,
                                uint64_t Cap, bool &IsLTorLE, bool &IsGEorGT) {
  IsLTorLE = false;
  IsGEorGT = false;
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  const Expr *PtrSide = nullptr;
  const Expr *ConstSide = nullptr;
  // We expect the loop variable on one side and a constant on the other.
  if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
    if (DRE->getDecl() == IVar) {
      PtrSide = LHS;
      ConstSide = RHS;
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(RHS)) {
    if (DRE->getDecl() == IVar) {
      PtrSide = RHS;
      ConstSide = LHS;
    }
  }
  if (!PtrSide || !ConstSide) return false;

  llvm::APSInt CVal;
  if (!evalInt(Ctx, ConstSide, CVal)) return false;
  uint64_t Num = CVal.getLimitedValue();

  // Must match the same Cap
  if (Num != Cap) return false;

  switch (BO->getOpcode()) {
  case BO_LT:
  case BO_LE:
    IsLTorLE = true;
    return true;
  case BO_GE:
  case BO_GT:
    IsGEorGT = true;
    return true;
  default:
    break;
  }
  return false;
}

static bool isGuardedByEnclosingIfLtCap(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                        const VarDecl *IVar, uint64_t Cap) {
  if (!ASE) return false;

  // Walk up the parents and look for an IfStmt where ASE is located within the 'then' branch
  // and the condition is i < Cap (or i <= Cap).
  const Stmt *Curr = ASE;
  while (true) {
    const Stmt *ParentS = nullptr;
    auto Parents = const_cast<ASTContext &>(Ctx).getParentMapContext().getParents(*Curr);
    if (Parents.empty()) break;
    ParentS = Parents[0].get<Stmt>();
    if (!ParentS) break;

    if (const auto *IS = dyn_cast<IfStmt>(ParentS)) {
      bool IsLTorLE = false, IsGEorGT = false;
      if (parseGuardCondition(Ctx, IS->getCond(), IVar, Cap, IsLTorLE, IsGEorGT)) {
        if (IsLTorLE) {
          const Stmt *Then = IS->getThen();
          if (Then && stmtContains(Then, ASE))
            return true;
        }
      }
    }
    Curr = ParentS;
  }

  return false;
}

static bool isGuardedByPrevIfGeBreak(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                     const VarDecl *IVar, uint64_t Cap) {
  if (!ASE) return false;

  // Find the nearest enclosing CompoundStmt and check previous siblings.
  const Stmt *Containing = ASE;
  const CompoundStmt *CS = nullptr;
  const Stmt *Tmp = Containing;
  while (true) {
    auto Parents = const_cast<ASTContext &>(Ctx).getParentMapContext().getParents(*Tmp);
    if (Parents.empty()) break;
    const Stmt *P = Parents[0].get<Stmt>();
    if (!P) break;
    if ((CS = dyn_cast<CompoundStmt>(P)))
      break;
    Tmp = P;
  }
  if (!CS) return false;

  // Find which immediate child statement of CS contains ASE.
  const Stmt *ContainerChild = nullptr;
  unsigned Index = 0, FoundIndex = 0;
  for (const Stmt *Child : CS->body()) {
    if (Child && stmtContains(Child, ASE)) {
      ContainerChild = Child;
      FoundIndex = Index;
      break;
    }
    ++Index;
  }
  if (!ContainerChild) return false;

  // Scan previous statements for if (i >= Cap) { break; } or return; or continue;
  Index = 0;
  for (const Stmt *Child : CS->body()) {
    if (Index >= FoundIndex) break;
    ++Index;

    const auto *IS = dyn_cast<IfStmt>(Child);
    if (!IS) continue;

    bool IsLTorLE = false, IsGEorGT = false;
    if (!parseGuardCondition(Ctx, IS->getCond(), IVar, Cap, IsLTorLE, IsGEorGT))
      continue;

    if (!IsGEorGT)
      continue;

    const Stmt *Then = IS->getThen();
    if (!Then) continue;

    // Look for a BreakStmt, ContinueStmt or ReturnStmt inside the then-branch.
    struct FindTerminator : public RecursiveASTVisitor<FindTerminator> {
      bool Found = false;
      bool VisitBreakStmt(BreakStmt *) { Found = true; return false; }
      bool VisitContinueStmt(ContinueStmt *) { Found = true; return false; }
      bool VisitReturnStmt(ReturnStmt *) { Found = true; return false; }
    } Finder;
    Finder.TraverseStmt(const_cast<Stmt*>(Then));

    if (Finder.Found)
      return true;
  }

  return false;
}

static bool isGuardedBeforeUse(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                               const VarDecl *IVar, uint64_t Cap) {
  // Two heuristics:
  // 1) ASE is inside an enclosing if (i < Cap) { ... ASE ... }
  if (isGuardedByEnclosingIfLtCap(Ctx, ASE, IVar, Cap))
    return true;

  // 2) Just before ASE in the same block, there is if (i >= Cap) { break; } or return; or continue;
  if (isGuardedByPrevIfGeBreak(Ctx, ASE, IVar, Cap))
    return true;

  return false;
}

bool SAGenTestChecker::getLoopIndexAndBounds(const ForStmt *FS, const ASTContext &Ctx,
                                             const VarDecl *&IVar, llvm::APSInt &LB,
                                             llvm::APSInt &UBExclusive) {
  IVar = nullptr;

  // Parse init: either "int i = 0" or "i = 0"
  const Stmt *Init = FS->getInit();
  if (!Init) return false;

  const VarDecl *IdxVar = nullptr;
  llvm::APSInt InitVal;

  if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
    if (!DS->isSingleDecl()) return false;
    const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
    if (!VD) return false;
    if (!VD->hasInit()) return false;
    if (!evalInt(Ctx, VD->getInit(), InitVal)) return false;
    IdxVar = VD;
  } else if (const auto *BO = dyn_cast<BinaryOperator>(Init)) {
    if (BO->getOpcode() != BO_Assign) return false;
    const auto *LHS = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
    if (!LHS) return false;
    const auto *VD = dyn_cast<VarDecl>(LHS->getDecl());
    if (!VD) return false;
    if (!evalInt(Ctx, BO->getRHS(), InitVal)) return false;
    IdxVar = VD;
  } else {
    return false;
  }

  // We only handle LB == 0
  if (InitVal != 0) return false;

  // Parse condition: i < N or i <= N
  const Expr *Cond = FS->getCond();
  if (!Cond) return false;
  const auto *CBO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!CBO) return false;

  BinaryOperator::Opcode Op = CBO->getOpcode();
  if (Op != BO_LT && Op != BO_LE) return false;

  const auto *LHS = dyn_cast<DeclRefExpr>(CBO->getLHS()->IgnoreParenImpCasts());
  if (!LHS) return false;
  if (LHS->getDecl() != IdxVar) return false;

  llvm::APSInt RHSVal;
  if (!evalInt(Ctx, CBO->getRHS(), RHSVal)) return false;

  // Compute UBExclusive
  if (Op == BO_LT) {
    UBExclusive = RHSVal;
  } else {
    // i <= N  => UBExclusive = N + 1
    UBExclusive = RHSVal + 1;
  }

  LB = InitVal;
  IVar = IdxVar;
  return true;
}

void SAGenTestChecker::reportIssue(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                                   uint64_t UBExclusive, uint64_t Cap,
                                   BugReporter &BR, const ASTContext &Ctx) const {
  if (!ASE || !IVar) return;

  SmallString<128> Msg;
  llvm::raw_svector_ostream OS(Msg);
  OS << "Loop bound exceeds array capacity: index '" << IVar->getName()
     << "' goes up to " << (UBExclusive ? (UBExclusive - 1) : 0)
     << " but array size is " << Cap;

  PathDiagnosticLocation ELoc(ASE->getIdx()->getExprLoc(), BR.getSourceManager());
  auto R = std::make_unique<BasicBugReport>(*BT, OS.str(), ELoc);
  R->addRange(ASE->getSourceRange());
  BR.emitReport(std::move(R));
}

void SAGenTestChecker::processForStmt(const ForStmt *FS, const ASTContext &Ctx, BugReporter &BR) const {
  const VarDecl *IVar = nullptr;
  llvm::APSInt LB, UBEx;
  if (!getLoopIndexAndBounds(FS, Ctx, IVar, LB, UBEx))
    return;

  // Only consider LB == 0 (already filtered)
  uint64_t UBExclusive = UBEx.getLimitedValue();

  // Traverse the loop body to find array subscripts using IVar.
  struct ASEVisitor : public RecursiveASTVisitor<ASEVisitor> {
    const ASTContext &Ctx;
    const VarDecl *IVar;
    uint64_t UBExclusive;
    BugReporter &BR;
    const SAGenTestChecker *Checker;

    ASEVisitor(const ASTContext &C, const VarDecl *V, uint64_t UB, BugReporter &B,
               const SAGenTestChecker *Ch)
      : Ctx(C), IVar(V), UBExclusive(UB), BR(B), Checker(Ch) {}

    bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
      const Expr *Idx = ASE->getIdx();
      if (!Idx) return true;

      // Filter out known false positives early.
      if (isFalsePositive(ASE))
        return true;

      // Only consider subscripts where the index is directly the loop variable.
      if (!indexIsDirectLoopVar(Idx, IVar))
        return true;

      uint64_t Cap = 0;
      if (!getArrayConstSizeFromBase(Ctx, ASE->getBase(), Cap))
        return true;

      // If guarded appropriately, skip.
      if (isGuardedBeforeUse(Ctx, ASE, IVar, Cap))
        return true;

      if (UBExclusive > Cap) {
        Checker->reportIssue(ASE, IVar, UBExclusive, Cap, BR, Ctx);
      }

      return true;
    }
  };

  if (const Stmt *Body = FS->getBody()) {
    ASEVisitor V(Ctx, IVar, UBExclusive, BR, this);
    V.TraverseStmt(const_cast<Stmt*>(Body));
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D) return;
  const Stmt *Body = D->getBody();
  if (!Body) return;
  const ASTContext &Ctx = Mgr.getASTContext();

  struct ForVisitor : public RecursiveASTVisitor<ForVisitor> {
    const ASTContext &Ctx;
    BugReporter &BR;
    const SAGenTestChecker *Checker;

    ForVisitor(const ASTContext &C, BugReporter &B, const SAGenTestChecker *Ch)
      : Ctx(C), BR(B), Checker(Ch) {}

    bool VisitForStmt(ForStmt *FS) {
      Checker->processForStmt(FS, Ctx, BR);
      return true;
    }
  };

  ForVisitor V(Ctx, BR, this);
  V.TraverseStmt(const_cast<Stmt*>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect loops whose upper bound exceeds the capacity of arrays indexed by the loop variable",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
