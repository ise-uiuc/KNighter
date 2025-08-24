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
#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::Bind
  > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Racy per-CPU field update", "Concurrency")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isPerCpuPtrCallee(const CallEvent &Call, CheckerContext &C);
      static bool isCompoundAssign(const BinaryOperator *BO);
      static bool isIncDec(const UnaryOperator *UO);
      static const MemRegion* getRootAlias(const MemRegion *R, ProgramStateRef State);
      static bool isPerCpuBaseRegion(const MemRegion *R, ProgramStateRef State);
      static const MemRegion* getMemberBaseRegion(const MemberExpr *ME, CheckerContext &C);
      static bool sameFieldRegion(const MemberExpr *A, const MemberExpr *B, CheckerContext &C);
      static bool protectedByREAD_ONCE(const Expr *E, CheckerContext &C);
      static bool protectedByWRITE_ONCE(const Expr *E, CheckerContext &C);
      static bool isSmallIntegerLike(QualType T, ASTContext &AC);
      void report(CheckerContext &C, const Stmt *S, StringRef Msg) const;
};

bool SAGenTestChecker::isPerCpuPtrCallee(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Best-effort: check if source text contains the macro/function name
  return ExprHasName(Origin, "this_cpu_ptr", C) ||
         ExprHasName(Origin, "per_cpu_ptr", C) ||
         ExprHasName(Origin, "raw_cpu_ptr", C);
}

bool SAGenTestChecker::isCompoundAssign(const BinaryOperator *BO) {
  if (!BO)
    return false;
  BinaryOperator::Opcode Op = BO->getOpcode();
  switch (Op) {
    case BO_AddAssign:
    case BO_SubAssign:
    case BO_MulAssign:
    case BO_DivAssign:
    case BO_RemAssign:
    case BO_AndAssign:
    case BO_OrAssign:
    case BO_XorAssign:
    case BO_ShlAssign:
    case BO_ShrAssign:
      return true;
    default:
      return false;
  }
}

bool SAGenTestChecker::isIncDec(const UnaryOperator *UO) {
  if (!UO)
    return false;
  UnaryOperator::Opcode Op = UO->getOpcode();
  return Op == UO_PreInc || Op == UO_PreDec || Op == UO_PostInc || Op == UO_PostDec;
}

const MemRegion* SAGenTestChecker::getRootAlias(const MemRegion *R, ProgramStateRef State) {
  if (!R)
    return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break;
    if (const MemRegion *const *Next = State->get<PtrAliasMap>(Cur)) {
      Cur = (*Next)->getBaseRegion();
      continue;
    }
    break;
  }
  return Cur;
}

bool SAGenTestChecker::isPerCpuBaseRegion(const MemRegion *R, ProgramStateRef State) {
  if (!R)
    return false;
  R = R->getBaseRegion();
  const MemRegion *Root = getRootAlias(R, State);
  if (!Root)
    Root = R;
  const bool *Flag = State->get<PerCpuPtrMap>(Root);
  return Flag && *Flag;
}

const MemRegion* SAGenTestChecker::getMemberBaseRegion(const MemberExpr *ME, CheckerContext &C) {
  if (!ME)
    return nullptr;
  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

bool SAGenTestChecker::sameFieldRegion(const MemberExpr *A, const MemberExpr *B, CheckerContext &C) {
  if (!A || !B)
    return false;
  // Same field declaration?
  if (A->getMemberDecl() != B->getMemberDecl())
    return false;
  // Same base object region?
  const MemRegion *RA = getMemberBaseRegion(A, C);
  const MemRegion *RB = getMemberBaseRegion(B, C);
  if (!RA || !RB)
    return false;
  return RA == RB;
}

bool SAGenTestChecker::protectedByREAD_ONCE(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "READ_ONCE", C);
}

bool SAGenTestChecker::protectedByWRITE_ONCE(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "WRITE_ONCE", C);
}

bool SAGenTestChecker::isSmallIntegerLike(QualType T, ASTContext &AC) {
  if (T.isNull())
    return false;
  if (!(T->isIntegerType() || T->isEnumeralType()))
    return false;
  // Focus on small scalars susceptible to torn accesses (<= 64 bits)
  unsigned Bits = AC.getTypeSize(T);
  return Bits > 0 && Bits <= 64;
}

void SAGenTestChecker::report(CheckerContext &C, const Stmt *S, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// Mark per-CPU pointers when returned from this_cpu_ptr/per_cpu_ptr/raw_cpu_ptr
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isPerCpuPtrCallee(Call, C))
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const MemRegion *RetReg = getMemRegionFromExpr(Origin, C);
  if (!RetReg)
    return;

  RetReg = RetReg->getBaseRegion();
  if (!RetReg)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<PerCpuPtrMap>(RetReg, true);
  C.addTransition(State);
}

// Propagate aliasing and detect racy updates to per-CPU fields
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // 1) Propagate aliasing of per-CPU pointers
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (LHSReg) {
      if (const MemRegion *RHSReg = Val.getAsRegion()) {
        RHSReg = RHSReg->getBaseRegion();
        if (RHSReg) {
          const MemRegion *Root = getRootAlias(RHSReg, State);
          if (!Root)
            Root = RHSReg;
          const bool *IsPerCPU = State->get<PerCpuPtrMap>(Root);
          if (IsPerCPU && *IsPerCPU) {
            State = State->set<PtrAliasMap>(LHSReg, Root);
            State = State->set<PtrAliasMap>(Root, LHSReg);
            State = State->set<PerCpuPtrMap>(LHSReg, true);
            C.addTransition(State);
            State = C.getState();
          }
        }
      }
    }
  }

  // 2) Detect non-atomic updates
  const BinaryOperator *BO = dyn_cast_or_null<BinaryOperator>(S);
  const UnaryOperator  *UO = dyn_cast_or_null<UnaryOperator>(S);

  // Compound assignment: x->f += ... etc.
  if (BO && isCompoundAssign(BO)) {
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const MemberExpr *LME = dyn_cast<MemberExpr>(LHS);
    if (!LME)
      return;

    if (!isSmallIntegerLike(LME->getType(), C.getASTContext()))
      return;

    const MemRegion *BaseR = getMemberBaseRegion(LME, C);
    if (!isPerCpuBaseRegion(BaseR, State))
      return;

    const Expr *BOExpr = dyn_cast<Expr>(S);
    if (protectedByREAD_ONCE(BOExpr, C) || protectedByWRITE_ONCE(BOExpr, C))
      return;

    report(C, S, "Non-atomic update to per-CPU field; use READ_ONCE/WRITE_ONCE.");
    return;
  }

  // ++x->f or --x->f
  if (UO && isIncDec(UO)) {
    const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
    const MemberExpr *ME = dyn_cast<MemberExpr>(Sub);
    if (!ME)
      return;

    if (!isSmallIntegerLike(ME->getType(), C.getASTContext()))
      return;

    const MemRegion *BaseR = getMemberBaseRegion(ME, C);
    if (!isPerCpuBaseRegion(BaseR, State))
      return;

    const Expr *UOExpr = dyn_cast<Expr>(S);
    if (protectedByREAD_ONCE(UOExpr, C) || protectedByWRITE_ONCE(UOExpr, C))
      return;

    report(C, S, "Non-atomic update to per-CPU field; use READ_ONCE/WRITE_ONCE.");
    return;
  }

  // Plain assignment: x->f = ...
  if (BO && BO->getOpcode() == BO_Assign) {
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const MemberExpr *LME = dyn_cast<MemberExpr>(LHS);
    if (!LME)
      return;

    if (!isSmallIntegerLike(LME->getType(), C.getASTContext()))
      return;

    const MemRegion *BaseR = getMemberBaseRegion(LME, C);
    if (!isPerCpuBaseRegion(BaseR, State))
      return;

    const Expr *BOExpr = dyn_cast<Expr>(S);
    if (protectedByWRITE_ONCE(BOExpr, C))
      return;

    // Subpattern 1: RMW via self-reference on RHS
    const MemberExpr *RHS_ME = findSpecificTypeInChildren<MemberExpr>(BO->getRHS());
    if (RHS_ME && sameFieldRegion(LME, RHS_ME, C)) {
      if (!protectedByREAD_ONCE(BO->getRHS(), C)) {
        report(C, S, "Plain read/modify/write of per-CPU field; use READ_ONCE/WRITE_ONCE.");
        return;
      }
    }

    // Subpattern 2: clear to zero
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, BO->getRHS(), C)) {
      if (EvalRes == 0) {
        report(C, S, "Clearing per-CPU field without WRITE_ONCE.");
        return;
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects plain (non-atomic) read/modify/write of per-CPU fields accessed cross-CPU; suggest READ_ONCE/WRITE_ONCE",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
