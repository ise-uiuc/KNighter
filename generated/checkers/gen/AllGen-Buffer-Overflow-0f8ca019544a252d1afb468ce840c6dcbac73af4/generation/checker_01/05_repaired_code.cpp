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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/Basic/OperatorKinds.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom ProgramState needed.

namespace {

class SAGenTestChecker : public Checker<check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Loop bound may exceed array size", "Array bounds")) {}

      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helper: get the DeclRef VarDecl from an expression if it is a simple variable reference.
      static const VarDecl *getIdxVarFromExpr(const Expr *E) {
        E = E ? E->IgnoreParenImpCasts() : nullptr;
        if (!E) return nullptr;
        if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
          return dyn_cast<VarDecl>(DRE->getDecl());
        }
        return nullptr;
      }

      // Helper: Try to get array size (AS) from base expression of subscript.
      static bool tryGetArraySizeFromBase(const Expr *Base, llvm::APSInt &AS, ASTContext &Ctx) {
        if (!Base) return false;

        // First, try helper for DeclRefExpr arrays
        llvm::APInt APSize;
        if (getArraySizeFromExpr(APSize, Base)) {
          AS = llvm::APSInt(APSize);
          return true;
        }

        // Strip implicit casts to find array-typed expression.
        const Expr *BNoImp = Base->IgnoreImpCasts();
        QualType T = BNoImp->getType();

        // If the expression's type is a ConstantArrayType, extract size directly.
        if (const auto *CAT = dyn_cast_or_null<ConstantArrayType>(T.getTypePtrOrNull())) {
          AS = llvm::APSInt(CAT->getSize());
          return true;
        }

        // If it's a MemberExpr, inspect the FieldDecl type.
        if (const auto *ME = dyn_cast<MemberExpr>(BNoImp)) {
          if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
            QualType FT = FD->getType();
            if (const auto *CAT2 = dyn_cast<ConstantArrayType>(FT.getTypePtrOrNull())) {
              AS = llvm::APSInt(CAT2->getSize());
              return true;
            }
          }
        }

        return false;
      }

      // Helper: Determine the induction variable of a ForStmt via its init.
      static const VarDecl *getForInductionVar(const ForStmt *FS) {
        if (!FS) return nullptr;
        const Stmt *Init = FS->getInit();
        if (!Init) return nullptr;

        if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
          if (DS->isSingleDecl()) {
            if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
              return VD;
            }
          }
        } else if (const auto *BO = dyn_cast<BinaryOperator>(Init)) {
          if (BO->getOpcode() == BO_Assign) {
            return getIdxVarFromExpr(BO->getLHS());
          }
        }
        return nullptr;
      }

      // Helper: Check if loop likely starts from 0: for (i = 0; ...).
      static bool loopStartsFromZero(const ForStmt *FS, const VarDecl *IdxVar, CheckerContext &C) {
        if (!FS || !IdxVar) return false;
        const Stmt *Init = FS->getInit();
        if (!Init) return false;

        if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
          if (DS->isSingleDecl()) {
            if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
              if (VD != IdxVar) return false;
              const Expr *InitE = VD->getInit();
              if (!InitE) return false;
              llvm::APSInt Val;
              if (EvaluateExprToInt(Val, InitE, C)) {
                return Val == 0;
              }
            }
          }
        } else if (const auto *BO = dyn_cast<BinaryOperator>(Init)) {
          if (BO->getOpcode() == BO_Assign) {
            const VarDecl *LHSVar = getIdxVarFromExpr(BO->getLHS());
            if (LHSVar != IdxVar) return false;
            llvm::APSInt Val;
            if (EvaluateExprToInt(Val, BO->getRHS(), C)) {
              return Val == 0;
            }
          }
        }
        return false;
      }

      // Helper: Extract loop upper bound for comparisons of form i < N, i <= N, N > i, N >= i.
      static bool extractUpperBound(const ForStmt *FS, const VarDecl *IdxVar,
                                    const Expr *&BoundExpr, BinaryOperatorKind &NormOp,
                                    CheckerContext &C) {
        if (!FS || !IdxVar) return false;
        const Expr *Cond = dyn_cast_or_null<Expr>(FS->getCond());
        if (!Cond) return false;

        Cond = Cond->IgnoreParenCasts();
        const auto *BO = dyn_cast<BinaryOperator>(Cond);
        if (!BO) return false;

        const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
        const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
        const VarDecl *LHSVar = getIdxVarFromExpr(LHS);
        const VarDecl *RHSVar = getIdxVarFromExpr(RHS);

        switch (BO->getOpcode()) {
        case BO_LT:
          if (LHSVar == IdxVar) {
            BoundExpr = RHS;
            NormOp = BO_LT;
            return true;
          }
          break;
        case BO_LE:
          if (LHSVar == IdxVar) {
            BoundExpr = RHS;
            NormOp = BO_LE;
            return true;
          }
          break;
        case BO_GT:
          if (RHSVar == IdxVar) {
            BoundExpr = LHS;
            NormOp = BO_LT; // N > i  ==> i < N
            return true;
          }
          break;
        case BO_GE:
          if (RHSVar == IdxVar) {
            BoundExpr = LHS;
            NormOp = BO_LE; // N >= i ==> i <= N
            return true;
          }
          break;
        default:
          break;
        }
        return false;
      }

      // Helper: Evaluate bound expression to integer upper bound if possible.
      static bool evalUpperBound(const Expr *BoundExpr, uint64_t &UBVal, CheckerContext &C) {
        if (!BoundExpr) return false;
        llvm::APSInt UB;
        if (EvaluateExprToInt(UB, BoundExpr, C)) {
          UBVal = UB.getLimitedValue();
          return true;
        }

        // Fall back to symbolic max if possible.
        ProgramStateRef State = C.getState();
        SVal BV = State->getSVal(BoundExpr, C.getLocationContext());
        if (SymbolRef Sym = BV.getAsSymbol()) {
          if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
            UBVal = MaxV->getLimitedValue();
            return true;
          }
        }
        return false;
      }

      // Helper: Try to find the controlling ForStmt for the given index variable by walking up parent ForStmts.
      static const ForStmt *findControllingForForIdx(const Stmt *Start, const VarDecl *IdxVar, CheckerContext &C) {
        const Stmt *Cur = Start;
        for (int depth = 0; depth < 4; ++depth) {
          const ForStmt *FS = findSpecificTypeInParents<ForStmt>(Cur, C);
          if (!FS) return nullptr;
          const VarDecl *IV = getForInductionVar(FS);
          if (IV == IdxVar)
            return FS;
          Cur = FS;
        }
        return nullptr;
      }

      // Helper: Simple ancestor IfStmt guard detection: if (i < AS) or (i <= AS-1) or (i >= AS) or (i > AS-1)
      static bool isGuardedByAncestorIfs(const Stmt *Start, const VarDecl *IdxVar,
                                         uint64_t ArraySize, CheckerContext &C) {
        const Stmt *Cur = Start;
        for (int tries = 0; tries < 2; ++tries) {
          const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Cur, C);
          if (!IS) return false;
          const Expr *Cond = IS->getCond();
          if (!Cond) return false;
          Cond = Cond->IgnoreParenCasts();

          if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
            const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
            const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
            const VarDecl *LHSVar = getIdxVarFromExpr(LHS);
            const VarDecl *RHSVar = getIdxVarFromExpr(RHS);

            llvm::APSInt Val;
            uint64_t K = 0;
            switch (BO->getOpcode()) {
            case BO_LT:
              if (LHSVar == IdxVar && EvaluateExprToInt(Val, RHS, C)) {
                K = Val.getLimitedValue();
                if (K == ArraySize) return true; // i < AS
              }
              break;
            case BO_LE:
              if (LHSVar == IdxVar && EvaluateExprToInt(Val, RHS, C)) {
                K = Val.getLimitedValue();
                if (K + 1 == ArraySize) return true; // i <= AS-1
              }
              break;
            case BO_GE:
              if (LHSVar == nullptr && RHSVar == IdxVar && EvaluateExprToInt(Val, LHS, C)) {
                K = Val.getLimitedValue();
                if (K == ArraySize) return true; // AS >= i  <=> i <= AS
              }
              if (LHSVar == IdxVar && EvaluateExprToInt(Val, RHS, C)) {
                // i >= AS (reject indices >= AS)
                K = Val.getLimitedValue();
                if (K == ArraySize) return true;
              }
              break;
            case BO_GT:
              if (LHSVar == nullptr && RHSVar == IdxVar && EvaluateExprToInt(Val, LHS, C)) {
                // AS > i  <=> i < AS
                K = Val.getLimitedValue();
                if (K == ArraySize) return true;
              }
              if (LHSVar == IdxVar && EvaluateExprToInt(Val, RHS, C)) {
                // i > AS-1
                K = Val.getLimitedValue();
                if (K + 1 == ArraySize) return true;
              }
              break;
            default:
              break;
            }
          }

          Cur = IS;
        }
        return false;
      }
};

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Look for an ArraySubscriptExpr that this location access corresponds to.
  const ArraySubscriptExpr *ASE = findSpecificTypeInParents<ArraySubscriptExpr>(S, C);
  if (!ASE)
    return;

  const Expr *Base = ASE->getBase();
  const Expr *IdxE  = ASE->getIdx();
  if (!Base || !IdxE)
    return;

  // We only handle the simple case arr[i] where i is a variable.
  const VarDecl *IdxVar = getIdxVarFromExpr(IdxE);
  if (!IdxVar)
    return;

  // Find the controlling ForStmt for this index variable.
  const ForStmt *CtrlFor = findControllingForForIdx(ASE, IdxVar, C);
  if (!CtrlFor)
    return;

  // Restrict to canonical loops i from 0 to UB with comparison < or <= (or equivalent).
  if (!loopStartsFromZero(CtrlFor, IdxVar, C))
    return;

  const Expr *BoundExpr = nullptr;
  BinaryOperatorKind NormOp;
  if (!extractUpperBound(CtrlFor, IdxVar, BoundExpr, NormOp, C))
    return;

  // Obtain numeric UB.
  uint64_t UBVal = 0;
  if (!evalUpperBound(BoundExpr, UBVal, C))
    return;

  // Obtain array compile-time size.
  llvm::APSInt AS;
  if (!tryGetArraySizeFromBase(Base, AS, C.getASTContext()))
    return;
  uint64_t ASVal = AS.getLimitedValue();

  // Early suppression if there is a nearby ancestor if-statement that guards against AS.
  if (isGuardedByAncestorIfs(ASE, IdxVar, ASVal, C))
    return;

  // Decide potential overflow from loop bound alone.
  bool PotentialOOB = false;
  if (NormOp == BO_LT) {
    // i in [0, UB) is safe only if UB <= AS.
    if (UBVal > ASVal)
      PotentialOOB = true;
  } else if (NormOp == BO_LE) {
    // i in [0, UB] is safe only if UB < AS.
    if (UBVal >= ASVal)
      PotentialOOB = true;
  }

  if (!PotentialOOB)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  llvm::SmallString<128> Msg;
  {
    llvm::raw_svector_ostream OS(Msg);
    OS << "Possible out-of-bounds: loop bound exceeds array size (bound=" << UBVal
       << ", size=" << ASVal << ")";
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg.str(), N);
  R->addRange(ASE->getSourceRange());
  if (const Expr *Cond = dyn_cast_or_null<Expr>(CtrlFor->getCond()))
    R->addRange(Cond->getSourceRange());

  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect array indexing guarded by a loop bound larger than the array size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
