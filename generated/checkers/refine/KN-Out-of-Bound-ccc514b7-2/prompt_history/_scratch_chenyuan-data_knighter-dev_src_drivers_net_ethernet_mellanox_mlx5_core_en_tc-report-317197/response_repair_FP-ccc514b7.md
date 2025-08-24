Refinement Plan:
- Root cause: The checker reports any occurrence where a loop iterates up to a larger bound and indexes a smaller array with the same index, but it doesn’t recognize intra-loop guards that ensure the smaller array isn’t indexed at the out-of-range value. In the reported false positive, the out-of-range access is prevented by a conditional operator (tt == MLX5_TT_ANY ? direct : indir[tt]), where the array access is only evaluated when tt != MLX5_TT_ANY and SmallSize = UB - 1, so tt ∈ [0, SmallSize-1].
- Fix approach:
  - Add precise suppression when the array subscript use is guarded by a branch condition on the loop index (IfStmt or ConditionalOperator) that logically implies i < SmallSize (or i <= SmallSize-1).
  - Handle common patterns: i < SmallSize, i <= SmallSize - 1, i >= SmallSize (else branch), i > SmallSize - 1 (else branch), and the “edge value exclusion” patterns i == SmallSize (else branch) or i != SmallSize (true branch), provided UB == SmallSize + 1.
  - Keep existing “break/return” guard suppression.
- Implementation details:
  - Parse branch conditions and normalize them relative to the loop index.
  - Determine which branch the array subscript belongs to by walking up the AST using ASTContext::getParents and checking subtree containment.
  - Only suppress when the guard provably keeps the index within [0, SmallSize-1].
- Edge cases and regressions:
  - Only suppress in narrowly defined, provably safe patterns.
  - Maintain detection for the AMD bug (no such guarding branch exists).
  - Avoid underflow when checking SmallSize - 1.
- Compatibility:
  - Keep existing includes; add minimal includes for parent queries. Ensure Clang-18 API compatibility.
  - No changes to existing utility includes are removed.

Refined Code:
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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include <optional>

// Added for parent queries and dyn typed nodes
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/ParentMapContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state is needed.

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
        const ArraySubscriptExpr *ExampleUse = nullptr; // Example use site for diagnostics
      };

      enum class GuardKind { None, Lt, Le, Gt, Ge, Eq, Ne };

      static bool evalToUInt64(const Expr *E, ASTContext &ACtx, uint64_t &Out);
      static bool isSimpleIncreasingIncrement(const Stmt *Inc, const VarDecl *IVar, ASTContext &ACtx);
      static bool isZeroInitOfVar(const Stmt *InitS, const VarDecl *IVar, ASTContext &ACtx);
      static bool isVarRefTo(const Expr *E, const VarDecl *VD);
      static bool getArrayDeclAndSizeFromBase(const Expr *Base, uint64_t &Size, const ValueDecl *&OutDecl);

      void processForStmt(const ForStmt *FS, ASTContext &ACtx, BugReporter &BR) const;
      void collectArrayUsesIndexedBy(const Stmt *Body, const VarDecl *IVar, ASTContext &ACtx,
                                     llvm::DenseMap<const ValueDecl*, ArrayUseInfo> &Out) const;
      bool hasGuardForBound(const Stmt *Body, const VarDecl *IVar, uint64_t SmallSize, ASTContext &ACtx) const;
      static bool condHasIVarAgainstConst(const Expr *CondE, const VarDecl *IVar, uint64_t ConstVal, ASTContext &ACtx);

      // New helpers to suppress false positives when the subscript is guarded by a branch.
      static bool containsStmt(const Stmt *Parent, const Stmt *Target);
      static bool parseCondOnIVar(const Expr *Cond, const VarDecl *IVar, uint64_t &Const, GuardKind &Kind, ASTContext &ACtx);
      static bool branchImpliesIndexInRange(GuardKind Kind, uint64_t Const, bool BranchWhenCondTrue,
                                            uint64_t SmallSize, uint64_t UB);
      static bool isIndexUseGuardedByBranch(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                                            uint64_t SmallSize, uint64_t UB, ASTContext &ACtx);
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

bool SAGenTestChecker::isVarRefTo(const Expr *E, const VarDecl *VD) {
  if (!E || !VD) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
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

  // Recursive walk
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
            // Sizes should match for the same decl; keep the example if not set.
            if (!It->second.ExampleUse)
              It->second.ExampleUse = ASE;
          }
        }
      }
    }

    // Recurse
    collectArrayUsesIndexedBy(Child, IVar, ACtx, Out);
  }
}

bool SAGenTestChecker::condHasIVarAgainstConst(const Expr *CondE, const VarDecl *IVar, uint64_t ConstVal, ASTContext &ACtx) {
  if (!CondE || !IVar) return false;

  CondE = CondE->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    // i >= ConstVal OR i == ConstVal
    if (isVarRefTo(BO->getLHS(), IVar)) {
      uint64_t Val;
      if (evalToUInt64(BO->getRHS(), ACtx, Val) && Val == ConstVal) {
        if (BO->getOpcode() == BO_GE || BO->getOpcode() == BO_EQ)
          return true;
      }
    }
    // ConstVal <= i (commuted form of i >= ConstVal)
    if (isVarRefTo(BO->getRHS(), IVar)) {
      uint64_t Val;
      if (evalToUInt64(BO->getLHS(), ACtx, Val) && Val == ConstVal) {
        if (BO->getOpcode() == BO_LE || BO->getOpcode() == BO_EQ)
          return true;
      }
    }
  }
  return false;
}

bool SAGenTestChecker::hasGuardForBound(const Stmt *Body, const VarDecl *IVar, uint64_t SmallSize, ASTContext &ACtx) const {
  if (!Body) return false;

  for (const Stmt *Child : Body->children()) {
    if (!Child) continue;

    if (const auto *IS = dyn_cast<IfStmt>(Child)) {
      const Expr *Cond = IS->getCond();
      if (condHasIVarAgainstConst(Cond, IVar, SmallSize, ACtx)) {
        // Check then-branch for break or return
        const Stmt *Then = IS->getThen();
        if (!Then) continue;
        if (findSpecificTypeInChildren<BreakStmt>(Then) ||
            findSpecificTypeInChildren<ReturnStmt>(Then)) {
          return true;
        }
      }
      // Also check nested statements within If
      if (hasGuardForBound(IS->getThen(), IVar, SmallSize, ACtx))
        return true;
      if (hasGuardForBound(IS->getElse(), IVar, SmallSize, ACtx))
        return true;
    } else {
      // Recurse
      if (hasGuardForBound(Child, IVar, SmallSize, ACtx))
        return true;
    }
  }

  return false;
}

// New: subtree containment helper.
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

// New: parse a simple binary condition on the loop index into a normalized form.
bool SAGenTestChecker::parseCondOnIVar(const Expr *Cond, const VarDecl *IVar, uint64_t &Const, GuardKind &Kind, ASTContext &ACtx) {
  Kind = GuardKind::None;
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  // i op Const
  if (isVarRefTo(L, IVar)) {
    uint64_t C;
    if (!evalToUInt64(R, ACtx, C))
      return false;
    Const = C;
    switch (BO->getOpcode()) {
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
    switch (BO->getOpcode()) {
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

// New: determine if a branch implies i within [0, SmallSize-1].
bool SAGenTestChecker::branchImpliesIndexInRange(GuardKind Kind, uint64_t Const, bool BranchWhenCondTrue,
                                                 uint64_t SmallSize, uint64_t UB) {
  if (Kind == GuardKind::None) return false;

  // We know from loop normalization that i starts at 0 and iterates up to UB-1.
  // We check common sufficient patterns.

  // Avoid underflow for SmallSize-1 checks.
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

// New: check if the actual array subscript is within a branch/conditional that keeps i in range.
bool SAGenTestChecker::isIndexUseGuardedByBranch(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                                                 uint64_t SmallSize, uint64_t UB, ASTContext &ACtx) {
  if (!ASE) return false;

  const Stmt *Node = ASE;
  // Walk up the parent chain (limit depth defensively).
  for (unsigned Depth = 0; Depth < 64 && Node; ++Depth) {
    auto Parents = ACtx.getParents(*Node);
    if (Parents.empty())
      break;

    const DynTypedNode &DN = Parents[0];
    if (const auto *CO = DN.get<ConditionalOperator>()) {
      uint64_t C = 0;
      GuardKind GK = GuardKind::None;
      if (!parseCondOnIVar(CO->getCond(), IVar, C, GK, ACtx)) {
        Node = CO;
        continue;
      }
      bool InTrue = containsStmt(CO->getTrueExpr(), ASE);
      bool InFalse = containsStmt(CO->getFalseExpr(), ASE);
      if (InTrue || InFalse) {
        bool BranchWhenCondTrue = InTrue;
        if (branchImpliesIndexInRange(GK, C, BranchWhenCondTrue, SmallSize, UB))
          return true;
      }
      Node = CO;
      continue;
    }

    if (const auto *IS = DN.get<IfStmt>()) {
      uint64_t C = 0;
      GuardKind GK = GuardKind::None;
      if (!parseCondOnIVar(IS->getCond(), IVar, C, GK, ACtx)) {
        Node = IS;
        continue;
      }
      const Stmt *ThenS = IS->getThen();
      const Stmt *ElseS = IS->getElse();
      bool InThen = ThenS && containsStmt(ThenS, ASE);
      bool InElse = ElseS && containsStmt(ElseS, ASE);
      if (InThen || InElse) {
        bool BranchWhenCondTrue = InThen; // then-branch executes when condition true
        if (branchImpliesIndexInRange(GK, C, BranchWhenCondTrue, SmallSize, UB))
          return true;
      }
      Node = IS;
      continue;
    }

    if (const auto *ParentStmt = DN.get<Stmt>()) {
      Node = ParentStmt;
      continue;
    } else {
      // No more Stmt parents (could be Decl); stop.
      break;
    }
  }

  return false;
}

void SAGenTestChecker::processForStmt(const ForStmt *FS, ASTContext &ACtx, BugReporter &BR) const {
  if (!FS) return;

  // Extract loop condition: expect i < UB or i <= UB
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

  // Adjust for <= bound: effective iteration count (UB is the count of iterations).
  if (Op == BO_LE)
    UB = UB + 1;

  // Check increment is a simple increasing increment
  if (!isSimpleIncreasingIncrement(FS->getInc(), IVar, ACtx))
    return;

  // Check initializer sets i = 0
  if (!isZeroInitOfVar(FS->getInit(), IVar, ACtx))
    return;

  // Collect array uses indexed by i
  llvm::DenseMap<const ValueDecl*, ArrayUseInfo> Uses;
  collectArrayUsesIndexedBy(FS->getBody(), IVar, ACtx, Uses);
  if (Uses.size() < 2)
    return; // Need at least two arrays A[i], B[i]

  // Find any array with size == UB
  bool HasBoundArray = false;
  for (const auto &It : Uses) {
    if (It.second.Size == UB) {
      HasBoundArray = true;
      break;
    }
  }
  if (!HasBoundArray)
    return;

  // Find a smaller array with size < UB
  const ArrayUseInfo *Small = nullptr;
  for (const auto &It : Uses) {
    if (It.second.Size < UB) {
      Small = &It.second;
      break;
    }
  }
  if (!Small)
    return;

  // Suppress if there is a loop-level guard like: if (i >= SmallSize) break/return;
  if (hasGuardForBound(FS->getBody(), IVar, Small->Size, ACtx))
    return;

  // Suppress if the specific use site is guarded by a branch/conditional ensuring i < SmallSize.
  if (Small->ExampleUse &&
      isIndexUseGuardedByBranch(Small->ExampleUse, IVar, Small->Size, UB, ACtx))
    return;

  // Report bug at the smaller array access site (if available), otherwise at the for condition
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

  // Simple recursive traversal to find ForStmt
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
```
