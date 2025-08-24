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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallString.h"
#include <optional>

// Added for parent queries and dyn typed nodes
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/ParentMapContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker< check::ASTCodeBody > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Mismatched loop bound and array size", "Array Bounds")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:
      struct ArrayUseInfo {
        const ValueDecl *VD = nullptr;                  // VarDecl or FieldDecl
        uint64_t Size = 0;                              // Constant array size
        const ArraySubscriptExpr *ExampleUse = nullptr; // Earliest example use site for diagnostics
      };

      enum class GuardKind { None, Lt, Le, Gt, Ge, Eq, Ne };
      enum class ExitKind { None, Continue, Break, Return };

      static bool evalToUInt64(const Expr *E, ASTContext &ACtx, uint64_t &Out);
      static bool evalToInt64(const Expr *E, ASTContext &ACtx, int64_t &Out);
      static bool isSimpleIncreasingIncrement(const Stmt *Inc, const VarDecl *IVar, ASTContext &ACtx);
      static bool isZeroInitOfVar(const Stmt *InitS, const VarDecl *IVar, ASTContext &ACtx);
      static bool isVarRefTo(const Expr *E, const VarDecl *VD);
      static bool exprContainsVarRef(const Expr *E, const VarDecl *VD);
      static bool getArrayDeclAndSizeFromBase(const Expr *Base, uint64_t &Size, const ValueDecl *&OutDecl);

      void processForStmt(const ForStmt *FS, ASTContext &ACtx, BugReporter &BR) const;
      void collectArrayUsesIndexedBy(const Stmt *Body, const VarDecl *IVar, ASTContext &ACtx,
                                     llvm::DenseMap<const ValueDecl*, ArrayUseInfo> &Out) const;

      // Existing simple loop-level guard heuristic (kept for compatibility).
      bool hasGuardForBound(const Stmt *Body, const VarDecl *IVar, uint64_t SmallSize, ASTContext &ACtx) const;

      // General helpers
      static bool containsStmt(const Stmt *Parent, const Stmt *Target);

      // Robust condition parsing: find relational on IVar anywhere in the condition subtree (handles StmtExpr, wrappers).
      static bool matchRelationalOnIVar(const BinaryOperator *BO, const VarDecl *IVar,
                                        uint64_t &Const, GuardKind &Kind, ASTContext &ACtx);
      static bool findRelationalOnIVarInStmt(const Stmt *S, const VarDecl *IVar,
                                             uint64_t &Const, GuardKind &Kind, ASTContext &ACtx);
      static bool parseCondOnIVar(const Expr *Cond, const VarDecl *IVar, uint64_t &Const, GuardKind &Kind, ASTContext &ACtx);
      static bool condHasIVarAgainstConst(const Expr *CondE, const VarDecl *IVar, uint64_t ConstVal, ASTContext &ACtx);

      // Parent-branch guard heuristic: if use is in a branch that ensures i < SmallSize
      static bool branchImpliesIndexInRange(GuardKind Kind, uint64_t Const, bool BranchWhenCondTrue,
                                            uint64_t SmallSize, uint64_t UB);
      static bool isIndexUseGuardedByBranch(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                                            uint64_t SmallSize, uint64_t UB, ASTContext &ACtx);

      // Mapping-guard suppression heuristic
      static const IfStmt *findEnclosingIfWithBranch(const Stmt *S, const Stmt *&OutBranch, ASTContext &ACtx);
      static bool parseMappingGuard(const Expr *Cond, const VarDecl *&InstVar, bool &ValidWhenTrue, ASTContext &ACtx);
      static const CompoundStmt *findDirectCompoundParent(const Stmt *S, ASTContext &ACtx);
      static bool hasPriorAssignFromIVar(const CompoundStmt *CS, const IfStmt *IS, const VarDecl *InstVar, const VarDecl *IVar);
      static bool branchContainsArrayIndexWithVar(const Stmt *Branch, const VarDecl *IdxVar);
      static bool isGuardedByIndexMapping(const ArraySubscriptExpr *ASE, const VarDecl *IVar, ASTContext &ACtx);

      // New: Early-exit-before-use guard heuristic to handle "if (i > S-1) continue;" style guards
      static ExitKind getSimpleEarlyExit(const Stmt *S);
      static bool branchImpliesIndexOutOfRange(GuardKind Kind, uint64_t Const, bool BranchWhenCondTrue,
                                               uint64_t SmallSize, ExitKind EK);
      static bool hasEarlyExitGuardBeforeUse(const ArraySubscriptExpr *Use, const VarDecl *IVar,
                                             uint64_t SmallSize, ASTContext &ACtx);
};

bool SAGenTestChecker::evalToUInt64(const Expr *E, ASTContext &ACtx, uint64_t &Out) {
  if (!E) return false;
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, ACtx)) {
    const llvm::APSInt &V = R.Val.getInt();
    Out = V.getZExtValue();
    return true;
  }
  return false;
}

bool SAGenTestChecker::evalToInt64(const Expr *E, ASTContext &ACtx, int64_t &Out) {
  if (!E) return false;
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, ACtx)) {
    const llvm::APSInt &V = R.Val.getInt();
    Out = V.getSExtValue();
    return true;
  }
  return false;
}

bool SAGenTestChecker::isVarRefTo(const Expr *E, const VarDecl *VD) {
  if (!E || !VD) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }
  return false;
}

bool SAGenTestChecker::exprContainsVarRef(const Expr *E, const VarDecl *VD) {
  if (!E || !VD) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child)) {
      if (exprContainsVarRef(CE, VD))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isZeroInitOfVar(const Stmt *InitS, const VarDecl *IVar, ASTContext &ACtx) {
  if (!InitS || !IVar) return false;

  // Case: declaration with initializer, e.g. "int i = 0;"
  if (const auto *DS = dyn_cast<DeclStmt>(InitS)) {
    for (const Decl *Di : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(Di)) {
        if (VD == IVar) {
          const Expr *Init = VD->getInit();
          uint64_t Val;
          if (Init && evalToUInt64(Init, ACtx, Val) && Val == 0)
            return true;
        }
      }
    }
  }

  // Case: assignment, e.g. "i = 0;"
  if (const auto *BO = dyn_cast<BinaryOperator>(InitS)) {
    if (BO->getOpcode() == BO_Assign && isVarRefTo(BO->getLHS(), IVar)) {
      uint64_t Val;
      if (evalToUInt64(BO->getRHS(), ACtx, Val) && Val == 0)
        return true;
    }
  }

  return false;
}

bool SAGenTestChecker::isSimpleIncreasingIncrement(const Stmt *Inc, const VarDecl *IVar, ASTContext &ACtx) {
  if (!Inc || !IVar) return false;

  // i++, ++i
  if (const auto *UO = dyn_cast<UnaryOperator>(Inc)) {
    if ((UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) &&
        isVarRefTo(UO->getSubExpr(), IVar))
      return true;
  }

  // i += 1;
  if (const auto *CAO = dyn_cast<CompoundAssignOperator>(Inc)) {
    if (CAO->getOpcode() == BO_AddAssign && isVarRefTo(CAO->getLHS(), IVar)) {
      uint64_t Val;
      if (evalToUInt64(CAO->getRHS(), ACtx, Val) && Val == 1)
        return true;
    }
  }

  // i = i + 1; or i = 1 + i;
  if (const auto *BO = dyn_cast<BinaryOperator>(Inc)) {
    if (BO->getOpcode() == BO_Assign && isVarRefTo(BO->getLHS(), IVar)) {
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (const auto *Add = dyn_cast<BinaryOperator>(RHS)) {
        if (Add->getOpcode() == BO_Add) {
          // i + 1
          if (isVarRefTo(Add->getLHS(), IVar)) {
            uint64_t Val;
            if (evalToUInt64(Add->getRHS(), ACtx, Val) && Val == 1)
              return true;
          }
          // 1 + i
          if (isVarRefTo(Add->getRHS(), IVar)) {
            uint64_t Val;
            if (evalToUInt64(Add->getLHS(), ACtx, Val) && Val == 1)
              return true;
          }
        }
      }
    }
  }

  return false;
}

bool SAGenTestChecker::getArrayDeclAndSizeFromBase(const Expr *Base, uint64_t &Size, const ValueDecl *&OutDecl) {
  if (!Base) return false;
  Base = Base->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        Size = CAT->getSize().getLimitedValue();
        OutDecl = VD;
        return true;
      }
    }
  }

  if (const auto *ME = dyn_cast<MemberExpr>(Base)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      QualType QT = FD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        Size = CAT->getSize().getLimitedValue();
        OutDecl = FD;
        return true;
      }
    }
  }

  return false;
}

void SAGenTestChecker::collectArrayUsesIndexedBy(const Stmt *Body, const VarDecl *IVar, ASTContext &ACtx,
                                                 llvm::DenseMap<const ValueDecl*, ArrayUseInfo> &Out) const {
  if (!Body || !IVar) return;

  for (const Stmt *Child : Body->children()) {
    if (!Child) continue;

    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Child)) {
      const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
      if (isVarRefTo(Idx, IVar)) {
        uint64_t Sz = 0;
        const ValueDecl *V = nullptr;
        const Expr *Base = ASE->getBase();
        if (getArrayDeclAndSizeFromBase(Base, Sz, V)) {
          auto It = Out.find(V);
          if (It == Out.end()) {
            ArrayUseInfo AU;
            AU.VD = V;
            AU.Size = Sz;
            AU.ExampleUse = ASE;
            Out.insert({V, AU});
          } else {
            // Keep the earliest example use (by source order).
            const SourceManager &SM = ACtx.getSourceManager();
            if (It->second.ExampleUse) {
              SourceLocation CurLoc = It->second.ExampleUse->getBeginLoc();
              SourceLocation NewLoc = ASE->getBeginLoc();
              if (SM.isBeforeInTranslationUnit(NewLoc, CurLoc)) {
                It->second.ExampleUse = ASE;
              }
            } else {
              It->second.ExampleUse = ASE;
            }
          }
        }
      }
    }

    // Recurse
    collectArrayUsesIndexedBy(Child, IVar, ACtx, Out);
  }
}

// New: robust matcher for relational operators on the loop index variable.
bool SAGenTestChecker::matchRelationalOnIVar(const BinaryOperator *BO, const VarDecl *IVar,
                                             uint64_t &Const, GuardKind &Kind, ASTContext &ACtx) {
  if (!BO || !IVar) return false;

  auto Op = BO->getOpcode();
  switch (Op) {
    case BO_LT: case BO_LE: case BO_GT: case BO_GE:
    case BO_EQ: case BO_NE:
      break;
    default:
      return false;
  }

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  // i op Const
  if (isVarRefTo(L, IVar)) {
    uint64_t C;
    if (!evalToUInt64(R, ACtx, C))
      return false;
    Const = C;
    switch (Op) {
      case BO_LT: Kind = GuardKind::Lt; break;
      case BO_LE: Kind = GuardKind::Le; break;
      case BO_GT: Kind = GuardKind::Gt; break;
      case BO_GE: Kind = GuardKind::Ge; break;
      case BO_EQ: Kind = GuardKind::Eq; break;
      case BO_NE: Kind = GuardKind::Ne; break;
      default: return false;
    }
    return true;
  }

  // Const op i  => normalize to i op' Const
  if (isVarRefTo(R, IVar)) {
    uint64_t C;
    if (!evalToUInt64(L, ACtx, C))
      return false;
    Const = C;
    switch (Op) {
      case BO_LT: Kind = GuardKind::Gt; break; // Const < i  => i > Const
      case BO_LE: Kind = GuardKind::Ge; break; // Const <= i => i >= Const
      case BO_GT: Kind = GuardKind::Lt; break; // Const > i  => i < Const
      case BO_GE: Kind = GuardKind::Le; break; // Const >= i => i <= Const
      case BO_EQ: Kind = GuardKind::Eq; break;
      case BO_NE: Kind = GuardKind::Ne; break;
      default: return false;
    }
    return true;
  }

  return false;
}

// Generic DFS over Stmt (handles StmtExpr body, wrapper expressions) to find a relational on IVar.
bool SAGenTestChecker::findRelationalOnIVarInStmt(const Stmt *S, const VarDecl *IVar,
                                                  uint64_t &Const, GuardKind &Kind, ASTContext &ACtx) {
  if (!S || !IVar) return false;

  if (const auto *E = dyn_cast<Expr>(S)) {
    const Expr *IE = E->IgnoreParenImpCasts();
    if (const auto *BO = dyn_cast<BinaryOperator>(IE)) {
      if (matchRelationalOnIVar(BO, IVar, Const, Kind, ACtx))
        return true;
    }
    // Fallthrough: inspect children of the expression
  }

  for (const Stmt *Ch : S->children()) {
    if (!Ch) continue;
    if (findRelationalOnIVarInStmt(Ch, IVar, Const, Kind, ACtx))
      return true;
  }

  return false;
}

bool SAGenTestChecker::parseCondOnIVar(const Expr *Cond, const VarDecl *IVar, uint64_t &Const, GuardKind &Kind, ASTContext &ACtx) {
  Kind = GuardKind::None;
  if (!Cond) return false;

  // Try a simple direct parse first.
  const Expr *C = Cond->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(C)) {
    if (matchRelationalOnIVar(BO, IVar, Const, Kind, ACtx))
      return true;
  }

  // Robust path: search anywhere within the condition subtree (handles macros like WARN_ON, likely/unlikely, StmtExpr).
  // Since Expr is a Stmt, reuse the Stmt DFS.
  return findRelationalOnIVarInStmt(Cond, IVar, Const, Kind, ACtx);
}

bool SAGenTestChecker::condHasIVarAgainstConst(const Expr *CondE, const VarDecl *IVar, uint64_t ConstVal, ASTContext &ACtx) {
  uint64_t C = 0;
  GuardKind K = GuardKind::None;
  if (!parseCondOnIVar(CondE, IVar, C, K, ACtx))
    return false;

  // We only accept guards that conclusively guard i >= SmallSize or i == SmallSize.
  if ((K == GuardKind::Ge && C == ConstVal) ||
      (K == GuardKind::Eq && C == ConstVal))
    return true;

  // Also accept commuted forms already normalized by parseCondOnIVar.
  return false;
}

bool SAGenTestChecker::hasGuardForBound(const Stmt *Body, const VarDecl *IVar, uint64_t SmallSize, ASTContext &ACtx) const {
  if (!Body) return false;

  for (const Stmt *Child : Body->children()) {
    if (!Child) continue;

    if (const auto *IS = dyn_cast<IfStmt>(Child)) {
      const Expr *Cond = IS->getCond();
      if (condHasIVarAgainstConst(Cond, IVar, SmallSize, ACtx)) {
        const Stmt *Then = IS->getThen();
        if (!Then) continue;
        if (findSpecificTypeInChildren<BreakStmt>(Then) ||
            findSpecificTypeInChildren<ReturnStmt>(Then)) {
          return true;
        }
      }
      if (hasGuardForBound(IS->getThen(), IVar, SmallSize, ACtx))
        return true;
      if (hasGuardForBound(IS->getElse(), IVar, SmallSize, ACtx))
        return true;
    } else {
      if (hasGuardForBound(Child, IVar, SmallSize, ACtx))
        return true;
    }
  }

  return false;
}

bool SAGenTestChecker::containsStmt(const Stmt *Parent, const Stmt *Target) {
  if (!Parent || !Target) return false;
  if (Parent == Target) return true;
  for (const Stmt *Child : Parent->children()) {
    if (!Child) continue;
    if (containsStmt(Child, Target))
      return true;
  }
  return false;
}

bool SAGenTestChecker::branchImpliesIndexInRange(GuardKind Kind, uint64_t Const, bool BranchWhenCondTrue,
                                                 uint64_t SmallSize, uint64_t UB) {
  if (Kind == GuardKind::None) return false;

  auto hasSmallMinus1 = [](uint64_t S, uint64_t &Out) -> bool {
    if (S == 0) return false;
    Out = S - 1;
    return true;
  };

  uint64_t S1 = 0;
  switch (Kind) {
    case GuardKind::Lt:
      // i < Const ; true-branch safe if Const == SmallSize.
      if (BranchWhenCondTrue && Const == SmallSize)
        return true;
      break;
    case GuardKind::Le:
      // i <= Const ; true-branch safe if Const == SmallSize - 1
      if (BranchWhenCondTrue && hasSmallMinus1(SmallSize, S1) && Const == S1)
        return true;
      break;
    case GuardKind::Ge:
      // i >= Const ; false-branch safe if Const == SmallSize
      if (!BranchWhenCondTrue && Const == SmallSize)
        return true;
      break;
    case GuardKind::Gt:
      // i > Const ; false-branch safe if Const == SmallSize - 1
      if (!BranchWhenCondTrue && hasSmallMinus1(SmallSize, S1) && Const == S1)
        return true;
      break;
    case GuardKind::Eq:
      // i == Const ; false-branch safe if Const == SmallSize and UB == SmallSize + 1
      if (!BranchWhenCondTrue && Const == SmallSize && UB == SmallSize + 1)
        return true;
      break;
    case GuardKind::Ne:
      // i != Const ; true-branch safe if Const == SmallSize and UB == SmallSize + 1
      if (BranchWhenCondTrue && Const == SmallSize && UB == SmallSize + 1)
        return true;
      break;
    default:
      break;
  }
  return false;
}

// Robust ancestor BFS to find an enclosing If/?: that guards i.
bool SAGenTestChecker::isIndexUseGuardedByBranch(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                                                 uint64_t SmallSize, uint64_t UB, ASTContext &ACtx) {
  if (!ASE) return false;

  // BFS over ancestors to find closest IfStmt or ConditionalOperator that contains the use.
  llvm::SmallVector<const Stmt*, 16> WL;
  llvm::SmallPtrSet<const Stmt*, 32> Visited;
  WL.push_back(ASE);
  Visited.insert(ASE);

  unsigned Steps = 0, MaxSteps = 256;

  while (!WL.empty() && Steps++ < MaxSteps) {
    const Stmt *Node = WL.pop_back_val();

    auto Parents = ACtx.getParents(*Node);
    for (const DynTypedNode &DN : Parents) {
      if (const auto *CO = DN.get<ConditionalOperator>()) {
        uint64_t C = 0;
        GuardKind GK = GuardKind::None;
        if (parseCondOnIVar(CO->getCond(), IVar, C, GK, ACtx)) {
          bool InTrue = containsStmt(CO->getTrueExpr(), ASE);
          bool InFalse = containsStmt(CO->getFalseExpr(), ASE);
          if (InTrue || InFalse) {
            bool BranchWhenCondTrue = InTrue;
            if (branchImpliesIndexInRange(GK, C, BranchWhenCondTrue, SmallSize, UB))
              return true;
          }
        }
        if (!Visited.count(CO)) { Visited.insert(CO); WL.push_back(CO); }
        continue;
      }

      if (const auto *IS = DN.get<IfStmt>()) {
        uint64_t C = 0;
        GuardKind GK = GuardKind::None;
        if (parseCondOnIVar(IS->getCond(), IVar, C, GK, ACtx)) {
          const Stmt *ThenS = IS->getThen();
          const Stmt *ElseS = IS->getElse();
          bool InThen = ThenS && containsStmt(ThenS, ASE);
          bool InElse = ElseS && containsStmt(ElseS, ASE);
          if (InThen || InElse) {
            bool BranchWhenCondTrue = InThen;
            if (branchImpliesIndexInRange(GK, C, BranchWhenCondTrue, SmallSize, UB))
              return true;
          }
        }
        if (!Visited.count(IS)) { Visited.insert(IS); WL.push_back(IS); }
        continue;
      }

      if (const auto *PStmt = DN.get<Stmt>()) {
        if (!Visited.count(PStmt)) { Visited.insert(PStmt); WL.push_back(PStmt); }
        continue;
      }
    }
  }

  return false;
}

// Find nearest enclosing IfStmt that contains S and output the branch (then/else) subtree containing S.
// Robust with multi-parent BFS; returns the closest by ancestor distance.
const IfStmt *SAGenTestChecker::findEnclosingIfWithBranch(const Stmt *S, const Stmt *&OutBranch, ASTContext &ACtx) {
  OutBranch = nullptr;
  if (!S) return nullptr;

  llvm::SmallVector<const Stmt*, 16> WL;
  llvm::SmallPtrSet<const Stmt*, 32> Visited;
  WL.push_back(S);
  Visited.insert(S);

  unsigned Steps = 0, MaxSteps = 256;

  while (!WL.empty() && Steps++ < MaxSteps) {
    const Stmt *Node = WL.pop_back_val();

    auto Parents = ACtx.getParents(*Node);
    for (const DynTypedNode &DN : Parents) {
      if (const auto *IS = DN.get<IfStmt>()) {
        const Stmt *ThenS = IS->getThen();
        const Stmt *ElseS = IS->getElse();
        if (ThenS && containsStmt(ThenS, S)) {
          OutBranch = ThenS;
          return IS;
        }
        if (ElseS && containsStmt(ElseS, S)) {
          OutBranch = ElseS;
          return IS;
        }
        if (!Visited.count(IS)) { Visited.insert(IS); WL.push_back(IS); }
        continue;
      }
      if (const auto *P = DN.get<Stmt>()) {
        if (!Visited.count(P)) { Visited.insert(P); WL.push_back(P); }
      }
    }
  }
  return nullptr;
}

bool SAGenTestChecker::parseMappingGuard(const Expr *Cond, const VarDecl *&InstVar, bool &ValidWhenTrue, ASTContext &ACtx) {
  InstVar = nullptr;
  ValidWhenTrue = false;
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  auto asVar = [](const Expr *E) -> const VarDecl* {
    if (!E) return nullptr;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
      return dyn_cast<VarDecl>(DRE->getDecl());
    return nullptr;
  };

  auto asConst = [&](const Expr *E, int64_t &C) -> bool {
    return evalToInt64(E, ACtx, C);
  };

  if (const VarDecl *VD = asVar(L)) {
    int64_t Cst;
    if (!asConst(R, Cst))
      return false;
    switch (BO->getOpcode()) {
      case BO_GE: if (Cst == 0) { InstVar = VD; ValidWhenTrue = true; return true; } break;
      case BO_GT: if (Cst == -1){ InstVar = VD; ValidWhenTrue = true; return true; } break;
      case BO_NE: if (Cst == -1){ InstVar = VD; ValidWhenTrue = true; return true; } break;
      case BO_EQ: if (Cst == -1){ InstVar = VD; ValidWhenTrue = false; return true; } break;
      case BO_LT: if (Cst == 0) { InstVar = VD; ValidWhenTrue = false; return true; } break;
      case BO_LE: if (Cst == -1){ InstVar = VD; ValidWhenTrue = false; return true; } break;
      default: break;
    }
    return false;
  }

  if (const VarDecl *VD = asVar(R)) {
    int64_t Cst;
    if (!asConst(L, Cst))
      return false;
    switch (BO->getOpcode()) {
      case BO_LE: if (Cst == 0) { InstVar = VD; ValidWhenTrue = true; return true; } break;
      case BO_LT: if (Cst == -1){ InstVar = VD; ValidWhenTrue = true; return true; } break;
      case BO_NE: if (Cst == -1){ InstVar = VD; ValidWhenTrue = true; return true; } break;
      case BO_EQ: if (Cst == -1){ InstVar = VD; ValidWhenTrue = false; return true; } break;
      case BO_GT: if (Cst == 0) { InstVar = VD; ValidWhenTrue = false; return true; } break;
      case BO_GE: if (Cst == -1){ InstVar = VD; ValidWhenTrue = false; return true; } break;
      default: break;
    }
    return false;
  }

  return false;
}

const CompoundStmt *SAGenTestChecker::findDirectCompoundParent(const Stmt *S, ASTContext &ACtx) {
  if (!S) return nullptr;

  llvm::SmallVector<const Stmt*, 16> WL;
  llvm::SmallPtrSet<const Stmt*, 32> Visited;
  WL.push_back(S);
  Visited.insert(S);

  unsigned Steps = 0, MaxSteps = 256;

  while (!WL.empty() && Steps++ < MaxSteps) {
    const Stmt *Node = WL.pop_back_val();

    auto Parents = ACtx.getParents(*Node);
    for (const DynTypedNode &DN : Parents) {
      if (const auto *CS = DN.get<CompoundStmt>()) {
        // Ensure Node is a direct child of CS.
        for (const Stmt *Ch : CS->body()) {
          if (Ch == Node)
            return CS;
        }
        if (!Visited.count(CS)) { Visited.insert(CS); WL.push_back(CS); }
        continue;
      }
      if (const auto *P = DN.get<Stmt>()) {
        if (!Visited.count(P)) { Visited.insert(P); WL.push_back(P); }
      }
    }
  }
  return nullptr;
}

bool SAGenTestChecker::hasPriorAssignFromIVar(const CompoundStmt *CS, const IfStmt *IS, const VarDecl *InstVar, const VarDecl *IVar) {
  if (!CS || !IS || !InstVar || !IVar) return false;

  for (const Stmt *Ch : CS->body()) {
    if (Ch == IS)
      break;

    if (const auto *DS = dyn_cast<DeclStmt>(Ch)) {
      for (const Decl *Di : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(Di)) {
          if (VD == InstVar) {
            const Expr *Init = VD->getInit();
            if (Init && exprContainsVarRef(Init, IVar))
              return true;
          }
        }
      }
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(Ch)) {
      if (BO->getOpcode() == BO_Assign) {
        const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
        if (const auto *LDR = dyn_cast<DeclRefExpr>(L)) {
          if (LDR->getDecl() == InstVar) {
            const Expr *RHS = BO->getRHS();
            if (RHS && exprContainsVarRef(RHS, IVar))
              return true;
          }
        }
      }
    }
  }
  return false;
}

bool SAGenTestChecker::branchContainsArrayIndexWithVar(const Stmt *Branch, const VarDecl *IdxVar) {
  if (!Branch || !IdxVar) return false;
  for (const Stmt *Ch : Branch->children()) {
    if (!Ch) continue;
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Ch)) {
      const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Idx)) {
        if (DRE->getDecl() == IdxVar)
          return true;
      }
    }
    if (branchContainsArrayIndexWithVar(Ch, IdxVar))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isGuardedByIndexMapping(const ArraySubscriptExpr *ASE, const VarDecl *IVar, ASTContext &ACtx) {
  if (!ASE || !IVar) return false;

  const Stmt *Branch = nullptr;
  const IfStmt *IS = findEnclosingIfWithBranch(ASE, Branch, ACtx);
  if (!IS || !Branch)
    return false;

  const VarDecl *InstVar = nullptr;
  bool ValidWhenTrue = false;
  if (!parseMappingGuard(IS->getCond(), InstVar, ValidWhenTrue, ACtx) || !InstVar)
    return false;

  bool InThen = containsStmt(IS->getThen(), ASE);
  bool InElse = IS->getElse() && containsStmt(IS->getElse(), ASE);
  if (!( (ValidWhenTrue && InThen) || (!ValidWhenTrue && InElse) ))
    return false;

  const CompoundStmt *CS = findDirectCompoundParent(IS, ACtx);
  if (!hasPriorAssignFromIVar(CS, IS, InstVar, IVar))
    return false;

  if (!branchContainsArrayIndexWithVar(Branch, InstVar))
    return false;

  return true;
}

SAGenTestChecker::ExitKind SAGenTestChecker::getSimpleEarlyExit(const Stmt *S) {
  if (!S) return ExitKind::None;

  if (isa<ContinueStmt>(S))
    return ExitKind::Continue;
  if (isa<BreakStmt>(S))
    return ExitKind::Break;
  if (isa<ReturnStmt>(S))
    return ExitKind::Return;

  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    // Accept only a single-statement compound of the exit.
    const Stmt *Only = nullptr;
    for (const Stmt *Ch : CS->body()) {
      if (!Ch) continue;
      if (Only) {
        Only = nullptr; // multiple statements -> not simple
        break;
      }
      Only = Ch;
    }
    if (Only)
      return getSimpleEarlyExit(Only);
  }

  return ExitKind::None;
}

bool SAGenTestChecker::branchImpliesIndexOutOfRange(GuardKind Kind, uint64_t Const, bool BranchWhenCondTrue,
                                                    uint64_t SmallSize, ExitKind EK) {
  if (Kind == GuardKind::None || EK == ExitKind::None) return false;

  auto hasSmallMinus1 = [](uint64_t S, uint64_t &Out) -> bool {
    if (S == 0) return false;
    Out = S - 1;
    return true;
  };

  bool IsContinue = (EK == ExitKind::Continue);
  bool IsBreakOrReturn = (EK == ExitKind::Break || EK == ExitKind::Return);

  uint64_t S1 = 0;
  bool HasS1 = hasSmallMinus1(SmallSize, S1);

  if (BranchWhenCondTrue) {
    // Then-branch exits.
    switch (Kind) {
      case GuardKind::Ge:
        if (Const == SmallSize) return true; // i >= S
        break;
      case GuardKind::Gt:
        if (HasS1 && Const == S1) return true; // i > S-1
        break;
      case GuardKind::Eq:
        if (IsBreakOrReturn && Const == SmallSize) return true; // i == S, terminate loop
        break;
      default:
        break;
    }
  } else {
    // Else-branch exits.
    switch (Kind) {
      case GuardKind::Lt:
        if (Const == SmallSize) return true; // !(i < S) => i >= S
        break;
      case GuardKind::Le:
        if (HasS1 && Const == S1) return true; // !(i <= S-1) => i >= S
        break;
      case GuardKind::Ne:
        if (IsBreakOrReturn && Const == SmallSize) return true; // !(i != S) => i == S
        break;
      default:
        break;
    }
  }

  // For continue, disallow equality-based one-off guards (they don't protect the whole tail).
  if (IsContinue) {
    // Already enforced above by only allowing Ge/Gt and Lt/Le exact thresholds.
  }

  return false;
}

bool SAGenTestChecker::hasEarlyExitGuardBeforeUse(const ArraySubscriptExpr *Use, const VarDecl *IVar,
                                                  uint64_t SmallSize, ASTContext &ACtx) {
  if (!Use || !IVar) return false;

  const Stmt *Node = Use;

  // Climb ancestors; at each direct compound parent, scan earlier siblings for a guarding if.
  for (unsigned Depth = 0; Depth < 64 && Node; ++Depth) {
    const CompoundStmt *CS = nullptr;

    // Find the immediate compound that directly contains Node as a child subtree.
    CS = findDirectCompoundParent(Node, ACtx);
    if (!CS)
      break;

    // Identify which child contains Node, and scan earlier siblings for guarding If.
    unsigned IndexOfChild = 0;
    bool FoundChild = false;
    for (const Stmt *Ch : CS->body()) {
      if (!Ch) { ++IndexOfChild; continue; }
      if (containsStmt(Ch, Node)) {
        FoundChild = true;
        break;
      }
      ++IndexOfChild;
    }

    if (FoundChild) {
      unsigned CurIdx = 0;
      for (const Stmt *Ch : CS->body()) {
        if (!Ch) { ++CurIdx; continue; }
        if (CurIdx >= IndexOfChild)
          break;

        if (const auto *IS = dyn_cast<IfStmt>(Ch)) {
          uint64_t C = 0;
          GuardKind GK = GuardKind::None;
          if (!parseCondOnIVar(IS->getCond(), IVar, C, GK, ACtx)) {
            ++CurIdx;
            continue;
          }

          ExitKind ThenEK = getSimpleEarlyExit(IS->getThen());
          ExitKind ElseEK = getSimpleEarlyExit(IS->getElse());

          if (ThenEK != ExitKind::None) {
            if (branchImpliesIndexOutOfRange(GK, C, /*BranchWhenCondTrue=*/true, SmallSize, ThenEK))
              return true;
          }
          if (ElseEK != ExitKind::None) {
            if (branchImpliesIndexOutOfRange(GK, C, /*BranchWhenCondTrue=*/false, SmallSize, ElseEK))
              return true;
          }
        }

        ++CurIdx;
      }
    }

    // Move Node up to this compound to continue climbing.
    Node = CS;
  }

  return false;
}

void SAGenTestChecker::processForStmt(const ForStmt *FS, ASTContext &ACtx, BugReporter &BR) const {
  if (!FS) return;

  const Expr *Cond = FS->getCond();
  if (!Cond) return;

  const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!BO) return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_LT && Op != BO_LE)
    return;

  const auto *LHSRef = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
  if (!LHSRef) return;
  const auto *IVar = dyn_cast<VarDecl>(LHSRef->getDecl());
  if (!IVar) return;

  uint64_t UB = 0;
  if (!evalToUInt64(BO->getRHS(), ACtx, UB))
    return;

  if (Op == BO_LE)
    UB = UB + 1;

  if (!isSimpleIncreasingIncrement(FS->getInc(), IVar, ACtx))
    return;

  if (!isZeroInitOfVar(FS->getInit(), IVar, ACtx))
    return;

  llvm::DenseMap<const ValueDecl*, ArrayUseInfo> Uses;
  collectArrayUsesIndexedBy(FS->getBody(), IVar, ACtx, Uses);
  if (Uses.size() < 2)
    return;

  bool HasBoundArray = false;
  for (const auto &It : Uses) {
    if (It.second.Size == UB) {
      HasBoundArray = true;
      break;
    }
  }
  if (!HasBoundArray)
    return;

  const ArrayUseInfo *Small = nullptr;
  for (const auto &It : Uses) {
    if (It.second.Size < UB) {
      Small = &It.second;
      break;
    }
  }
  if (!Small)
    return;

  // Suppress classic loop-tail early exit guards, including macro-wrapped conditions (e.g., WARN_ON).
  if (hasGuardForBound(FS->getBody(), IVar, Small->Size, ACtx))
    return;

  // Suppress if this specific use is inside a branch that implies i is in range.
  if (Small->ExampleUse &&
      isIndexUseGuardedByBranch(Small->ExampleUse, IVar, Small->Size, UB, ACtx))
    return;

  // Suppress for mapping guards that effectively tie another index to i.
  if (Small->ExampleUse &&
      isGuardedByIndexMapping(Small->ExampleUse, IVar, ACtx))
    return;

  // Suppress when earlier sibling statements perform an early-exit once i is out of range.
  if (Small->ExampleUse &&
      hasEarlyExitGuardBeforeUse(Small->ExampleUse, IVar, Small->Size, ACtx))
    return;

  SourceLocation Loc;
  if (Small->ExampleUse)
    Loc = Small->ExampleUse->getExprLoc();
  else
    Loc = FS->getLParenLoc();

  std::string Msg = "Loop bound uses size of one array but also indexes a smaller array with the same index; possible out-of-bounds";
  if (const auto *ND = dyn_cast<NamedDecl>(Small->VD)) {
    llvm::SmallString<128> Buf;
    llvm::raw_svector_ostream OS(Buf);
    OS << " (bound=" << UB << ", array '" << ND->getName() << "' size=" << Small->Size << ")";
    Msg += OS.str().str();
  } else {
    llvm::SmallString<64> Buf;
    llvm::raw_svector_ostream OS(Buf);
    OS << " (bound=" << UB << ", smaller array size=" << Small->Size << ")";
    Msg += OS.str().str();
  }

  PathDiagnosticLocation PDL(Loc, BR.getSourceManager());
  auto R = std::make_unique<BasicBugReport>(*BT, Msg, PDL);
  if (Small->ExampleUse)
    R->addRange(Small->ExampleUse->getSourceRange());
  BR.emitReport(std::move(R));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D) return;
  const Stmt *Body = D->getBody();
  if (!Body) return;

  ASTContext &ACtx = Mgr.getASTContext();

  llvm::SmallVector<const Stmt*, 16> Stack;
  Stack.push_back(Body);
  while (!Stack.empty()) {
    const Stmt *S = Stack.pop_back_val();
    if (!S) continue;

    if (const auto *FS = dyn_cast<ForStmt>(S)) {
      processForStmt(FS, ACtx, BR);
    }

    for (const Stmt *Child : S->children()) {
      if (Child)
        Stack.push_back(Child);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects loops bounded by one array's size while indexing a smaller array with the same index",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
