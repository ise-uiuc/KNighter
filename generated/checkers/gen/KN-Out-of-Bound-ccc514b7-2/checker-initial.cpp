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
        const ValueDecl *VD = nullptr;               // VarDecl or FieldDecl
        uint64_t Size = 0;                           // Constant array size
        const ArraySubscriptExpr *ExampleUse = nullptr; // Example use site for diagnostics
      };

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

  // Adjust for <= bound: effective iteration count
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

  // Suppress if there is a guard like: if (i >= SmallSize) break/return;
  if (hasGuardForBound(FS->getBody(), IVar, Small->Size, ACtx))
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

  auto R = std::make_unique<BasicBugReport>(*BT, Msg, PathDiagnosticLocation::createBegin(Loc, BR.getSourceManager()));
  if (Small->ExampleUse)
    R->addRange(Small->ExampleUse->getSourceRange());
  R->setDeclWithIssue(FS->getBeginLoc());
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
