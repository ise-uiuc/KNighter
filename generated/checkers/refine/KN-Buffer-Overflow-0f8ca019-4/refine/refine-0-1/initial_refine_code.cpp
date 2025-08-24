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

// This is an AST-only checker.

namespace {

// Forward declarations of helpers
static bool evalInt(const ASTContext &Ctx, const Expr *E, llvm::APSInt &Res);
static bool containsDeclRefToVar(const Expr *E, const VarDecl *V);
static bool indexIsDirectLoopVar(const Expr *Idx, const VarDecl *IVar);
static bool getArrayConstSizeFromBase(const ASTContext &Ctx, const Expr *Base, uint64_t &CapOut);
static bool stmtContains(const Stmt *Root, const Stmt *Target);

// Guard analysis helpers
static bool extractIVarCmpConst(const ASTContext &Ctx, const Expr *Cond,
                                const VarDecl *IVar, BinaryOperatorKind &OpOut,
                                llvm::APSInt &KOut);
static bool findAnyIVarCmpInBoolExpr(const ASTContext &Ctx, const Expr *Cond,
                                     const VarDecl *IVar, BinaryOperatorKind &OpOut,
                                     llvm::APSInt &KOut);
static bool isGuardedByEnclosingIfLtK(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                      const VarDecl *IVar, uint64_t Cap);
static bool isGuardedByPrevIfGeKTerminator(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                           const VarDecl *IVar, uint64_t Cap);
static bool isGuardedBeforeUse(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                               const VarDecl *IVar, uint64_t Cap);

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

  // Allow trivial unary plus on the variable.
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

// Normalize a comparison so that it is always in the form: (IVar <op> K)
static bool extractIVarCmpConst(const ASTContext &Ctx, const Expr *Cond,
                                const VarDecl *IVar, BinaryOperatorKind &OpOut,
                                llvm::APSInt &KOut) {
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;

  BinaryOperatorKind Op = BO->getOpcode();
  // Only consider comparison ops.
  if (Op != BO_LT && Op != BO_LE && Op != BO_GT && Op != BO_GE &&
      Op != BO_EQ && Op != BO_NE)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  const DeclRefExpr *LHSVar = dyn_cast<DeclRefExpr>(LHS);
  const DeclRefExpr *RHSVar = dyn_cast<DeclRefExpr>(RHS);

  llvm::APSInt K;
  // Case: IVar on LHS.
  if (LHSVar && LHSVar->getDecl() == IVar) {
    if (!evalInt(Ctx, RHS, K)) return false;
    OpOut = Op;
    KOut = K;
    return true;
  }
  // Case: IVar on RHS -> normalize by flipping operator.
  if (RHSVar && RHSVar->getDecl() == IVar) {
    if (!evalInt(Ctx, LHS, K)) return false;

    // Flip operator: K ? i  -> i ?' K
    switch (Op) {
      case BO_LT: OpOut = BO_GT; break; // K < i  -> i > K
      case BO_LE: OpOut = BO_GE; break; // K <= i -> i >= K
      case BO_GT: OpOut = BO_LT; break; // K > i  -> i < K
      case BO_GE: OpOut = BO_LE; break; // K >= i -> i <= K
      case BO_EQ: OpOut = BO_EQ; break;
      case BO_NE: OpOut = BO_NE; break;
      default: return false;
    }
    KOut = K;
    return true;
  }

  return false;
}

// Search inside a boolean expression tree (handling && and ||) for any comparison
// involving IVar and an integer constant. Returns the first match found.
static bool findAnyIVarCmpInBoolExpr(const ASTContext &Ctx, const Expr *Cond,
                                     const VarDecl *IVar, BinaryOperatorKind &OpOut,
                                     llvm::APSInt &KOut) {
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();
  // Try direct comparison first.
  if (extractIVarCmpConst(Ctx, Cond, IVar, OpOut, KOut))
    return true;

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
      // Search both sides; prefer left-to-right occurrence.
      if (findAnyIVarCmpInBoolExpr(Ctx, BO->getLHS(), IVar, OpOut, KOut))
        return true;
      if (findAnyIVarCmpInBoolExpr(Ctx, BO->getRHS(), IVar, OpOut, KOut))
        return true;
    }
    // We ignore other ops.
  }
  return false;
}

// Enclosing guard: if (i < K) { ... ASE ... } is safe if K <= Cap.
static bool isGuardedByEnclosingIfLtK(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                      const VarDecl *IVar, uint64_t Cap) {
  if (!ASE) return false;

  const Stmt *Curr = ASE;
  while (true) {
    const Stmt *ParentS = nullptr;
    auto Parents = const_cast<ASTContext &>(Ctx).getParentMapContext().getParents(*Curr);
    if (Parents.empty()) break;
    ParentS = Parents[0].get<Stmt>();
    if (!ParentS) break;

    if (const auto *IS = dyn_cast<IfStmt>(ParentS)) {
      BinaryOperatorKind Op;
      llvm::APSInt K;
      if (findAnyIVarCmpInBoolExpr(Ctx, IS->getCond(), IVar, Op, K)) {
        // Normalize safety condition for '<' and '<='
        if ((Op == BO_LT || Op == BO_LE)) {
          uint64_t KVal = K.getLimitedValue();
          // If the if-then branch (where ASE resides) enforces i < K and K <= Cap, it's safe.
          const Stmt *Then = IS->getThen();
          if (Then && stmtContains(Then, ASE) && KVal <= Cap)
            return true;
        }
      }
    }
    Curr = ParentS;
  }

  return false;
}

// Previous sibling guard: if (i >= K) { break/continue/return; } before ASE is safe if K >= Cap.
// Also accept 'i > K' as equivalent to 'i >= K+1'.
static bool isGuardedByPrevIfGeKTerminator(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                           const VarDecl *IVar, uint64_t Cap) {
  if (!ASE) return false;

  // Find the nearest enclosing CompoundStmt and check previous siblings.
  const CompoundStmt *CS = nullptr;
  const Stmt *Tmp = ASE;
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

  // Find the immediate child statement of CS that contains ASE.
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

  // Scan previous statements for if (i >= K) { break/continue/return; }
  Index = 0;
  for (const Stmt *Child : CS->body()) {
    if (Index >= FoundIndex) break;
    ++Index;

    const auto *IS = dyn_cast<IfStmt>(Child);
    if (!IS) continue;

    BinaryOperatorKind Op;
    llvm::APSInt K;
    if (!findAnyIVarCmpInBoolExpr(Ctx, IS->getCond(), IVar, Op, K))
      continue;

    uint64_t Threshold = 0;
    bool IsGeKind = false;
    if (Op == BO_GE) {
      Threshold = K.getLimitedValue();
      IsGeKind = true;
    } else if (Op == BO_GT) {
      // i > K  -> effectively i >= K+1 for termination
      Threshold = (K + 1).getLimitedValue();
      IsGeKind = true;
    } else {
      // Only >= or > form are used for this guard
      continue;
    }

    const Stmt *Then = IS->getThen();
    if (!Then) continue;

    struct FindTerminator : public RecursiveASTVisitor<FindTerminator> {
      bool Found = false;
      bool VisitBreakStmt(BreakStmt *) { Found = true; return false; }
      bool VisitContinueStmt(ContinueStmt *) { Found = true; return false; }
      bool VisitReturnStmt(ReturnStmt *) { Found = true; return false; }
    } Finder;
    Finder.TraverseStmt(const_cast<Stmt*>(Then));

    if (!Finder.Found)
      continue;

    // Guard is sufficient iff Threshold >= Cap
    if (IsGeKind && Threshold >= Cap)
      return true;
  }

  return false;
}

static bool isGuardedBeforeUse(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                               const VarDecl *IVar, uint64_t Cap) {
  // Heuristic 1:
  // ASE is inside an enclosing if (i < K) { ... ASE ... } with K <= Cap.
  if (isGuardedByEnclosingIfLtK(Ctx, ASE, IVar, Cap))
    return true;

  // Heuristic 2:
  // Just before ASE in the same block, there is:
  //   if (i >= K [or i > K]) { break; / continue; / return; }
  // with K (or K+1 for >) >= Cap.
  if (isGuardedByPrevIfGeKTerminator(Ctx, ASE, IVar, Cap))
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
