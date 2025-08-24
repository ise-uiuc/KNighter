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
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track which MemRegions are per-CPU pointers.
// Value: 1 = from this_cpu_ptr(), 2 = from per_cpu_ptr().
REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion*, unsigned)

namespace {
class SAGenTestChecker : public Checker<check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Non-atomic per-CPU access", "Concurrency")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isPerCpuCtorName(StringRef N);
      static bool isPerCpuType(QualType QT);
      static bool isConstInt(const Expr *E, CheckerContext &C, llvm::APSInt &Out);
      static bool isPerCpuCtorCall(const Expr *E, CheckerContext &C, unsigned &Kind);
      static bool isPerCpuBaseExpr(const Expr *Base, CheckerContext &C);
      static bool sameFieldRegion(const MemberExpr *E1, const MemberExpr *E2, CheckerContext &C);
      static bool rhsReadsSameField(const MemberExpr *LHSME, const Expr *RHS, CheckerContext &C);
      void reportAtME(const MemberExpr *ME, StringRef Msg, CheckerContext &C) const;
};

bool SAGenTestChecker::isPerCpuCtorName(StringRef N) {
  return N.equals("this_cpu_ptr") || N.equals("per_cpu_ptr");
}

bool SAGenTestChecker::isPerCpuCtorCall(const Expr *E, CheckerContext &C, unsigned &Kind) {
  if (!E) return false;
  const Expr *EE = E;
  // We avoid IgnoreImplicit() as per suggestions when extracting regions,
  // but for name check it's fine to just use the original expression text helper.
  if (ExprHasName(EE, "this_cpu_ptr", C)) {
    Kind = 1;
    return true;
  }
  if (ExprHasName(EE, "per_cpu_ptr", C)) {
    Kind = 2;
    return true;
  }
  return false;
}

bool SAGenTestChecker::isPerCpuType(QualType QT) {
  if (QT.isNull())
    return false;
  if (!QT->isPointerType())
    return false;

  QualType Pointee = QT->getPointeeType();
  if (Pointee.isNull())
    return false;

  if (const RecordType *RT = dyn_cast<RecordType>(Pointee.getTypePtr())) {
    const RecordDecl *RD = RT->getDecl();
    if (!RD)
      return false;
    StringRef Name = RD->getName();
    if (Name.empty())
      return false;
    // Heuristic: struct name contains "percpu" (case-insensitive)
    if (Name.contains_insensitive("percpu"))
      return true;
    // Or ends with "_percpu" (case-sensitive)
    if (Name.endswith("_percpu"))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isPerCpuBaseExpr(const Expr *Base, CheckerContext &C) {
  if (!Base)
    return false;

  // First, see if we tracked it as per-CPU pointer.
  if (const MemRegion *MR = getMemRegionFromExpr(Base, C)) {
    MR = MR->getBaseRegion();
    if (MR) {
      ProgramStateRef State = C.getState();
      if (State->get<PerCpuPtrMap>(MR))
        return true;
    }
  }

  // Fallback: heuristic via type name.
  QualType T = Base->getType();
  if (isPerCpuType(T))
    return true;

  return false;
}

bool SAGenTestChecker::isConstInt(const Expr *E, CheckerContext &C, llvm::APSInt &Out) {
  if (!E)
    return false;
  return EvaluateExprToInt(Out, E, C);
}

bool SAGenTestChecker::sameFieldRegion(const MemberExpr *E1, const MemberExpr *E2, CheckerContext &C) {
  if (!E1 || !E2)
    return false;

  const ValueDecl *MD1 = E1->getMemberDecl();
  const ValueDecl *MD2 = E2->getMemberDecl();
  if (!MD1 || !MD2)
    return false;

  // Compare the base regions for aliasing and the member declarations for the exact field.
  const MemRegion *R1 = getMemRegionFromExpr(E1, C);
  const MemRegion *R2 = getMemRegionFromExpr(E2, C);
  if (!R1 || !R2)
    return false;

  R1 = R1->getBaseRegion();
  R2 = R2->getBaseRegion();
  if (!R1 || !R2)
    return false;

  if (R1 != R2)
    return false;

  return MD1 == MD2;
}

bool SAGenTestChecker::rhsReadsSameField(const MemberExpr *LHSME, const Expr *RHS, CheckerContext &C) {
  if (!LHSME || !RHS)
    return false;
  const MemberExpr *Found = findSpecificTypeInChildren<MemberExpr>(RHS);
  if (!Found)
    return false;
  return sameFieldRegion(LHSME, Found, C);
}

void SAGenTestChecker::reportAtME(const MemberExpr *ME, StringRef Msg, CheckerContext &C) const {
  if (!ME) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(ME->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  // 1) Detect Compound Assignments on per-CPU fields: x += ..., x -= ..., etc.
  if (const auto *CAO = dyn_cast<CompoundAssignOperator>(S)) {
    const Expr *LHS = CAO->getLHS();
    const MemberExpr *LHSME = dyn_cast<MemberExpr>(LHS ? LHS->IgnoreParenCasts() : nullptr);
    if (LHSME && isPerCpuBaseExpr(LHSME->getBase(), C)) {
      reportAtME(LHSME, "Non-atomic read-modify-write on per-CPU field; use READ_ONCE()/WRITE_ONCE().", C);
      return;
    }
  }

  // 2) Detect ++/-- on per-CPU fields.
  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->isIncrementDecrementOp()) {
      const Expr *Sub = UO->getSubExpr();
      const MemberExpr *MEM = dyn_cast<MemberExpr>(Sub ? Sub->IgnoreParenCasts() : nullptr);
      if (MEM && isPerCpuBaseExpr(MEM->getBase(), C)) {
        reportAtME(MEM, "Non-atomic read-modify-write on per-CPU field; use READ_ONCE()/WRITE_ONCE().", C);
        return;
      }
    }
  }

  // 3) Assignments: track per-CPU pointers and detect writes to per-CPU fields.
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();

      // 3.A) Track per-CPU pointers: LHS = this_cpu_ptr(...) or per_cpu_ptr(...)
      if (LHS && RHS) {
        unsigned Kind = 0;
        if (isPerCpuCtorCall(RHS, C, Kind)) {
          if (const MemRegion *LHSReg = getMemRegionFromExpr(LHS, C)) {
            LHSReg = LHSReg->getBaseRegion();
            if (LHSReg) {
              State = State->set<PerCpuPtrMap>(LHSReg, Kind);
              Changed = true;
            }
          }
        } else {
          // 3.B) Pointer alias propagation: LHS = RHS (both pointers)
          QualType LHSTy = LHS->getType();
          QualType RHSTy = RHS->getType();
          if (!LHSTy.isNull() && !RHSTy.isNull() &&
              LHSTy->isPointerType() && RHSTy->isPointerType()) {
            const MemRegion *LHSReg = getMemRegionFromExpr(LHS, C);
            const MemRegion *RHSReg = getMemRegionFromExpr(RHS, C);
            if (LHSReg && RHSReg) {
              LHSReg = LHSReg->getBaseRegion();
              RHSReg = RHSReg->getBaseRegion();
              if (LHSReg && RHSReg) {
                if (const unsigned *RHSKind = State->get<PerCpuPtrMap>(RHSReg)) {
                  State = State->set<PerCpuPtrMap>(LHSReg, *RHSKind);
                  Changed = true;
                }
              }
            }
          }
        }
      }

      // 3.C) Detect writes to per-CPU fields:
      const MemberExpr *LHSME = dyn_cast<MemberExpr>(LHS ? LHS->IgnoreParenCasts() : nullptr);
      if (LHSME && isPerCpuBaseExpr(LHSME->getBase(), C)) {
        // Case 1: RMW via x = x + ...
        if (rhsReadsSameField(LHSME, RHS, C)) {
          reportAtME(LHSME, "Non-atomic read-modify-write on per-CPU field; use READ_ONCE()/WRITE_ONCE().", C);
          if (Changed) C.addTransition(State);
          return;
        }
        // Case 2: Plain write/reset: x = 0 (or any integer constant)
        llvm::APSInt ValInt;
        if (isConstInt(RHS, C, ValInt)) {
          reportAtME(LHSME, "Plain write to per-CPU field; use WRITE_ONCE().", C);
          if (Changed) C.addTransition(State);
          return;
        }
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect non-atomic RMW or plain writes on per-CPU fields; suggest READ_ONCE()/WRITE_ONCE()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
