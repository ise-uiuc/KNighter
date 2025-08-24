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
// Replaced by a more general extractor that recognizes simple derived indices.
static bool getArrayConstSizeFromBase(const ASTContext &Ctx, const Expr *Base, uint64_t &CapOut);
static bool stmtContains(const Stmt *Root, const Stmt *Target);
static bool parseGuardCondition(const ASTContext &Ctx, const Expr *Cond, const VarDecl *IVar,
                                uint64_t Cap, bool &IsLTorLE, bool &IsGEorGT);
static bool isGuardedByEnclosingIfLtCap(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                        const VarDecl *IVar, uint64_t Cap);
static bool isGuardedByPrevIfGeBreak(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                     const VarDecl *IVar, uint64_t Cap);
static bool isGuardedBeforeUse(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                               const VarDecl *IVar, uint64_t Cap, uint64_t UBExclusive);

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
static bool isFalsePositive(const ArraySubscriptExpr *ASE) {
  if (!ASE) return false;
  // If either the subscript expression itself, its base, or its index come from
  // a macro expansion, skip. Macros often hide bitset/packing tricks that the
  // AST-only checker cannot reason about safely.
  if (isFromMacro(ASE) || isFromMacro(ASE->getBase()) || isFromMacro(ASE->getIdx()))
    return true;
  return false;
}

// Strip no-op nodes for matching.
static const Expr *stripNoOps(const Expr *E) {
  if (!E) return nullptr;
  return E->IgnoreParenImpCasts();
}

// Try to evaluate an expression to an unsigned 64-bit constant.
// Returns true on success and sets Out.
static bool evalUInt64(const ASTContext &Ctx, const Expr *E, uint64_t &Out) {
  llvm::APSInt V;
  if (!evalInt(Ctx, E, V))
    return false;
  if (V.isSigned() && V.isNegative())
    return false;
  Out = V.getLimitedValue();
  return true;
}

// Recognize subscript index forms that are simple linear transforms of the loop variable.
// Supported forms:
//   - i
//   - i / K   (K > 0)
//   - i >> n  (n >= 0)
// Optionally allow addition/subtraction by 0 (no-op).
// Returns true if recognized and sets DivOut (>=1) and OffsetOut (currently only 0 supported).
static bool extractIndexDivAndOffset(const ASTContext &Ctx, const Expr *Idx,
                                     const VarDecl *IVar, uint64_t &DivOut,
                                     int64_t &OffsetOut) {
  DivOut = 0;
  OffsetOut = 0;
  if (!Idx || !IVar) return false;

  const Expr *E = stripNoOps(Idx);

  auto IsDirectLoopVar = [&](const Expr *X) -> bool {
    X = stripNoOps(X);
    if (const auto *DRE = dyn_cast<DeclRefExpr>(X))
      return DRE->getDecl() == IVar;
    return false;
  };

  // Direct variable: arr[i]
  if (IsDirectLoopVar(E)) {
    DivOut = 1;
    OffsetOut = 0;
    return true;
  }

  // Allow no-op +0 or -0 around recognized forms
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    // i / K
    if (Op == BO_Div) {
      if (IsDirectLoopVar(BO->getLHS())) {
        uint64_t K = 0;
        if (evalUInt64(Ctx, BO->getRHS(), K) && K > 0) {
          DivOut = K;
          OffsetOut = 0;
          return true;
        }
      }
    }

    // i >> n  => division by 2^n
    if (Op == BO_Shr) {
      if (IsDirectLoopVar(BO->getLHS())) {
        uint64_t N = 0;
        if (evalUInt64(Ctx, BO->getRHS(), N)) {
          if (N < 63) {
            DivOut = (1ULL << N);
            OffsetOut = 0;
            return true;
          }
        }
      }
    }

    // Handle +0 or -0 around a recognized form
    if (Op == BO_Add || Op == BO_Sub) {
      const Expr *L = BO->getLHS();
      const Expr *R = BO->getRHS();
      uint64_t CVal = 0;

      // Try left op as core form and right as constant 0
      uint64_t InnerDiv = 0;
      int64_t InnerOff = 0;
      if (evalUInt64(Ctx, R, CVal)) {
        if (CVal == 0 && extractIndexDivAndOffset(Ctx, L, IVar, InnerDiv, InnerOff)) {
          DivOut = InnerDiv;
          OffsetOut = InnerOff;
          return true;
        }
      }

      // Try right op as core form and left as constant 0, for commutative '+'
      if (Op == BO_Add && evalUInt64(Ctx, L, CVal)) {
        if (CVal == 0 && extractIndexDivAndOffset(Ctx, R, IVar, InnerDiv, InnerOff)) {
          DivOut = InnerDiv;
          OffsetOut = InnerOff;
          return true;
        }
      }
    }
  }

  return false;
}

// Safe ceil division for positive integers: ceil(A / B) with B >= 1.
static uint64_t ceilDivU64(uint64_t A, uint64_t B) {
  if (B == 0) return UINT64_MAX;
  return (A + B - 1) / B;
}

// Parse a comparator "IVar <op> Const" or "Const <op> IVar".
// Returns true and fills ConstVal and OpOut if matches; otherwise false.
static bool parseIVarVsConst(const ASTContext &Ctx, const Expr *Cond, const VarDecl *IVar,
                             uint64_t &ConstVal, BinaryOperator::Opcode &OpOut) {
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  switch (Op) {
  case BO_LT: case BO_LE:
  case BO_GT: case BO_GE:
  case BO_EQ: case BO_NE:
    break;
  default:
    return false;
  }

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  // IVar on LHS, constant on RHS
  if (const auto *DL = dyn_cast<DeclRefExpr>(LHS)) {
    if (DL->getDecl() == IVar) {
      llvm::APSInt Val;
      if (!evalInt(Ctx, RHS, Val)) return false;
      ConstVal = Val.getLimitedValue();
      OpOut = Op;
      return true;
    }
  }

  // IVar on RHS, constant on LHS: reverse comparison
  if (const auto *DR = dyn_cast<DeclRefExpr>(RHS)) {
    if (DR->getDecl() == IVar) {
      llvm::APSInt Val;
      if (!evalInt(Ctx, LHS, Val)) return false;
      ConstVal = Val.getLimitedValue();

      // Reverse the operator
      switch (Op) {
      case BO_LT: OpOut = BO_GT; break;
      case BO_LE: OpOut = BO_GE; break;
      case BO_GT: OpOut = BO_LT; break;
      case BO_GE: OpOut = BO_LE; break;
      case BO_EQ: OpOut = BO_EQ; break;
      case BO_NE: OpOut = BO_NE; break;
      default: return false;
      }
      return true;
    }
  }

  return false;
}

// Recursively detect if a condition contains a conjunct/disjunct or negated form
// that ensures i >= Cap in the THEN branch of an if-statement.
//
// Accepted patterns:
//   - i >= Cap
//   - !(i < Cap)
//   - Combined with && or || at any depth, e.g. (i >= Cap && X), (X || i >= Cap), !(i < Cap) || Y, etc.
// For usage with "if (Cond) { break/continue/return; }", any occurrence is enough to ensure
// that when i >= Cap, Cond is true and execution will not reach subsequent array uses.
static bool condMentionsIVarGeCapForThen(const ASTContext &Ctx, const Expr *Cond,
                                         const VarDecl *IVar, uint64_t Cap) {
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *PE = dyn_cast<ParenExpr>(Cond))
    return condMentionsIVarGeCapForThen(Ctx, PE->getSubExpr(), IVar, Cap);

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      // !(i < Cap) implies i >= Cap
      uint64_t CVal = 0;
      BinaryOperator::Opcode Op;
      if (parseIVarVsConst(Ctx, UO->getSubExpr(), IVar, CVal, Op)) {
        if (Op == BO_LT && CVal == Cap)
          return true;
      }
      // Otherwise, try recursively but conservatively do not attempt double negations
      return false;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->isLogicalOp()) {
      // For both && and ||, if any side contains "i >= Cap" (or !(i < Cap)),
      // then when i >= Cap the condition will be true at least in the || case.
      // For &&, this is heuristic; it matches common Linux "AND with mode flag"
      // pre-terminators (e.g. !(HT40) gating), and reduces FPs like ath9k.
      return condMentionsIVarGeCapForThen(Ctx, BO->getLHS(), IVar, Cap) ||
             condMentionsIVarGeCapForThen(Ctx, BO->getRHS(), IVar, Cap);
    }

    // Direct comparator
    uint64_t CVal = 0;
    BinaryOperator::Opcode Op;
    if (parseIVarVsConst(Ctx, BO, IVar, CVal, Op)) {
      if (CVal == Cap && (Op == BO_GE)) // only accept >= Cap exactly
        return true;
    }
  }

  // Also check the direct comparator case when Cond is itself a comparator not wrapped as BO
  uint64_t CVal = 0;
  BinaryOperator::Opcode Op;
  if (parseIVarVsConst(Ctx, Cond, IVar, CVal, Op)) {
    if (CVal == Cap && (Op == BO_GE))
      return true;
  }

  return false;
}

// Recursively detect if the THEN-branch of an if-statement implies i < Cap due to a
// conjunction containing i < Cap. We reject any condition containing '||' to avoid FNs.
static bool condEnsuresIVarLtCapForThen(const ASTContext &Ctx, const Expr *Cond,
                                        const VarDecl *IVar, uint64_t Cap) {
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *PE = dyn_cast<ParenExpr>(Cond))
    return condEnsuresIVarLtCapForThen(Ctx, PE->getSubExpr(), IVar, Cap);

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_LAnd) {
      // In A && B, THEN-branch requires both; it's safe if either conjunct includes (i < Cap).
      return condEnsuresIVarLtCapForThen(Ctx, BO->getLHS(), IVar, Cap) ||
             condEnsuresIVarLtCapForThen(Ctx, BO->getRHS(), IVar, Cap);
    }
    if (BO->getOpcode() == BO_LOr) {
      // Not safe to conclude i < Cap in general.
      return false;
    }

    uint64_t CVal = 0;
    BinaryOperator::Opcode Op;
    if (parseIVarVsConst(Ctx, BO, IVar, CVal, Op)) {
      if (Op == BO_LT && CVal == Cap)
        return true;
    }
    return false;
  }

  // Fallback: direct comparator
  uint64_t CVal = 0;
  BinaryOperator::Opcode Op;
  if (parseIVarVsConst(Ctx, Cond, IVar, CVal, Op)) {
    if (Op == BO_LT && CVal == Cap)
      return true;
  }

  return false;
}

// Determine if ASE is guarded by an enclosing IfStmt using a comparator between IVar and Cap.
// Additionally considers '==' and '!=' cases. For '!=' we require UBExclusive <= Cap + 1.
static bool isGuardedByEnclosingIfComparator(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                             const VarDecl *IVar, uint64_t Cap, uint64_t UBExclusive) {
  if (!ASE) return false;

  const Stmt *Curr = ASE;
  while (true) {
    const Stmt *ParentS = nullptr;
    auto Parents = const_cast<ASTContext &>(Ctx).getParentMapContext().getParents(*Curr);
    if (Parents.empty()) break;
    ParentS = Parents[0].get<Stmt>();
    if (!ParentS) break;

    if (const auto *IS = dyn_cast<IfStmt>(ParentS)) {
      uint64_t CVal = 0;
      BinaryOperator::Opcode Op;
      if (parseIVarVsConst(Ctx, IS->getCond(), IVar, CVal, Op)) {
        if (CVal == Cap) {
          const Stmt *Then = IS->getThen();
          const Stmt *Else = IS->getElse();

          auto InThen = Then && stmtContains(Then, ASE);
          auto InElse = Else && stmtContains(Else, ASE);

          switch (Op) {
          case BO_LT:
          case BO_LE:
            if (InThen) return true;
            break;
          case BO_GT:
          case BO_GE:
            if (InElse) return true;
            break;
          case BO_EQ:
            if (InElse) return true;
            break;
          case BO_NE:
            if (InThen && UBExclusive <= Cap + 1) return true;
            break;
          default:
            break;
          }
        }
      }
    }
    Curr = ParentS;
  }

  return false;
}

// Determine if ASE is guarded by a ConditionalOperator (?:) that compares IVar against Cap,
// and the branch containing ASE is safe. For '!=' we require UBExclusive <= Cap + 1.
static bool isGuardedByConditionalOperator(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                           const VarDecl *IVar, uint64_t Cap, uint64_t UBExclusive) {
  if (!ASE) return false;

  const Stmt *Curr = ASE;
  while (true) {
    const Stmt *ParentS = nullptr;
    auto Parents = const_cast<ASTContext &>(Ctx).getParentMapContext().getParents(*Curr);
    if (Parents.empty()) break;
    ParentS = Parents[0].get<Stmt>();
    if (!ParentS) break;

    if (const auto *CO = dyn_cast<ConditionalOperator>(ParentS)) {
      uint64_t CVal = 0;
      BinaryOperator::Opcode Op;
      if (parseIVarVsConst(Ctx, CO->getCond(), IVar, CVal, Op)) {
        if (CVal == Cap) {
          const Expr *TrueE = CO->getTrueExpr();
          const Expr *FalseE = CO->getFalseExpr();
          bool InTrue = TrueE && stmtContains(TrueE, ASE);
          bool InFalse = FalseE && stmtContains(FalseE, ASE);

          switch (Op) {
          case BO_LT:
          case BO_LE:
            if (InTrue) return true;
            break;
          case BO_GT:
          case BO_GE:
            if (InFalse) return true;
            break;
          case BO_EQ:
            if (InFalse) return true;
            break;
          case BO_NE:
            if (InTrue && UBExclusive <= Cap + 1) return true;
            break;
          default:
            break;
          }
        }
      }
    }

    Curr = ParentS;
  }

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
  // Returns true on success and sets IVar, LB, UBExclusive, CondOp, RHSValue.
  static bool getLoopIndexAndBounds(const ForStmt *FS, const ASTContext &Ctx,
                                    const VarDecl *&IVar, llvm::APSInt &LB,
                                    llvm::APSInt &UBExclusive,
                                    BinaryOperator::Opcode &CondOpOut,
                                    llvm::APSInt &RHSValueOut);

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

// Enhanced: accept "i < Cap" as a conjunct within &&-chains (reject ||) for then-branch safety.
static bool isGuardedByEnclosingIfLtCap(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
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
      const Stmt *Then = IS->getThen();
      if (Then && stmtContains(Then, ASE)) {
        if (condEnsuresIVarLtCapForThen(Ctx, IS->getCond(), IVar, Cap))
          return true;
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

  // Scan previous statements for if (cond) { break; } or continue; or return;
  Index = 0;
  for (const Stmt *Child : CS->body()) {
    if (Index >= FoundIndex) break;
    ++Index;

    const auto *IS = dyn_cast<IfStmt>(Child);
    if (!IS) continue;

    const Stmt *Then = IS->getThen();
    if (!Then) continue;

    // Check the condition contains a GE-cap (or !(LT-cap)) test
    if (!condMentionsIVarGeCapForThen(Ctx, IS->getCond(), IVar, Cap))
      continue;

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
                               const VarDecl *IVar, uint64_t Cap, uint64_t UBExclusive) {
  // Heuristic A: ASE is inside an enclosing if (i < Cap) [possibly && ...] { ... ASE ... }
  if (isGuardedByEnclosingIfLtCap(Ctx, ASE, IVar, Cap))
    return true;

  // Heuristic B: Just before ASE in the same block, there is if (cond) { break/continue/return; },
  // where cond contains i >= Cap (or !(i < Cap)) even inside a compound condition.
  if (isGuardedByPrevIfGeBreak(Ctx, ASE, IVar, Cap))
    return true;

  // Heuristic C: ASE is in a safe branch of a ConditionalOperator (?:) comparing i with Cap.
  if (isGuardedByConditionalOperator(Ctx, ASE, IVar, Cap, UBExclusive))
    return true;

  // Heuristic D: ASE is in a safe branch of an enclosing IfStmt using a comparator (==, !=, <, <=, >, >=) with Cap.
  if (isGuardedByEnclosingIfComparator(Ctx, ASE, IVar, Cap, UBExclusive))
    return true;

  return false;
}

//====================== Checker implementations ======================

bool SAGenTestChecker::getLoopIndexAndBounds(const ForStmt *FS, const ASTContext &Ctx,
                                             const VarDecl *&IVar, llvm::APSInt &LB,
                                             llvm::APSInt &UBExclusive,
                                             BinaryOperator::Opcode &CondOpOut,
                                             llvm::APSInt &RHSValueOut) {
  IVar = nullptr;
  CondOpOut = BO_Comma; // sentinel

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
  CondOpOut = Op;
  RHSValueOut = RHSVal;
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
  llvm::APSInt LB, UBEx, RHSVal;
  BinaryOperator::Opcode CondOp;
  if (!getLoopIndexAndBounds(FS, Ctx, IVar, LB, UBEx, CondOp, RHSVal))
    return;

  // Only consider LB == 0 (already filtered)
  uint64_t UBExclusive = UBEx.getLimitedValue();
  uint64_t RHSNumeric = RHSVal.getLimitedValue();

  // Traverse the loop body to find array subscripts using IVar.
  struct ASEVisitor : public RecursiveASTVisitor<ASEVisitor> {
    const ASTContext &Ctx;
    const VarDecl *IVar;
    uint64_t UBExclusive;
    uint64_t RHSNumeric;
    BinaryOperator::Opcode CondOp;
    BugReporter &BR;
    const SAGenTestChecker *Checker;

    ASEVisitor(const ASTContext &C, const VarDecl *V, uint64_t UB, uint64_t RHSN,
               BinaryOperator::Opcode Op, BugReporter &B, const SAGenTestChecker *Ch)
      : Ctx(C), IVar(V), UBExclusive(UB), RHSNumeric(RHSN), CondOp(Op), BR(B), Checker(Ch) {}

    bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
      const Expr *Idx = ASE->getIdx();
      if (!Idx) return true;

      // Filter out known false positives early.
      if (isFalsePositive(ASE))
        return true;

      uint64_t Cap = 0;
      if (!getArrayConstSizeFromBase(Ctx, ASE->getBase(), Cap))
        return true;

      // Only consider subscripts where the index is directly the loop variable
      // or a supported derived form (i, i/const, i>>const). Skip unknown forms to avoid FPs.
      uint64_t Div = 0;
      int64_t Offset = 0;
      if (!extractIndexDivAndOffset(Ctx, Idx, IVar, Div, Offset))
        return true;

      // If guarded appropriately (via if/?:), skip.
      if (isGuardedBeforeUse(Ctx, ASE, IVar, Cap, UBExclusive))
        return true;

      // Preserve the existing conservative suppression for "<=" when RHS equals the capacity
      // on the direct-indexing path (Div == 1). This avoids regressions unrelated to the target bug.
      if (Div == 1 && CondOp == BO_LE && RHSNumeric == Cap)
        return true;

      // Currently handle only zero offset to avoid accidental FPs.
      if (Offset != 0)
        return true;

      // For index forms of i/Div (Div>=1), the max subscript is floor((UBExclusive-1)/Div).
      // This is safe iff ceil(UBExclusive / Div) <= Cap.
      const uint64_t NeededSlots = ceilDivU64(UBExclusive, Div);
      if (NeededSlots > Cap) {
        Checker->reportIssue(ASE, IVar, UBExclusive, Cap, BR, Ctx);
      }

      return true;
    }
  };

  if (const Stmt *Body = FS->getBody()) {
    ASEVisitor V(Ctx, IVar, UBExclusive, RHSNumeric, CondOp, BR, this);
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
