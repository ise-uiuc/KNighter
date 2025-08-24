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
#include "clang/AST/Expr.h"
#include "clang/AST/ASTContext.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track per-path learned lower bounds for 'optlen' parameters.
REGISTER_MAP_WITH_PROGRAMSTATE(OptlenLBMap, const ParmVarDecl*, uint64_t)

namespace {

class SAGenTestChecker : public Checker<
    check::BranchCondition,
    check::PreCall
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unchecked optlen in setsockopt copy", "API Misuse")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static const ParmVarDecl *getOptlenParm(const FunctionDecl *FD);
      static ProgramStateRef setLB(ProgramStateRef S, const ParmVarDecl *P, uint64_t NewLB);
      static bool tryEvalToConst(const Expr *E, uint64_t &Out, CheckerContext &C);

      // Core logic to update LB for true/false branches
      void processOptlenCompareBranch(const Expr *CondE,
                                      const ParmVarDecl *OptlenParm,
                                      CheckerContext &C) const;
};

// Return the 'optlen' ParmVarDecl* if exists in the current function, else nullptr.
const ParmVarDecl *SAGenTestChecker::getOptlenParm(const FunctionDecl *FD) {
  if (!FD)
    return nullptr;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (P && P->getName() == "optlen")
      return P;
  }
  return nullptr;
}

// Update the lower bound for an 'optlen' parameter to max(old, NewLB).
ProgramStateRef SAGenTestChecker::setLB(ProgramStateRef S, const ParmVarDecl *P, uint64_t NewLB) {
  if (!S || !P)
    return S;
  if (const uint64_t *Old = S->get<OptlenLBMap>(P)) {
    uint64_t M = (*Old > NewLB) ? *Old : NewLB;
    if (M != *Old)
      return S->set<OptlenLBMap>(P, M);
    return S;
  }
  return S->set<OptlenLBMap>(P, NewLB);
}

// Evaluate expression to constant uint64_t if possible.
bool SAGenTestChecker::tryEvalToConst(const Expr *E, uint64_t &Out, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C)) {
    Out = Res.getZExtValue();
    return true;
  }
  return false;
}

// Analyze condition and create two transitions with updated LB when possible.
void SAGenTestChecker::processOptlenCompareBranch(const Expr *CondE,
                                                  const ParmVarDecl *OptlenParm,
                                                  CheckerContext &C) const {
  if (!CondE || !OptlenParm)
    return;

  const auto *BO = dyn_cast<BinaryOperator>(CondE->IgnoreParenCasts());
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  // Only consider comparison/equality ops.
  bool IsCompare =
      Op == BO_LT || Op == BO_LE || Op == BO_GT || Op == BO_GE || Op == BO_EQ;
  if (!IsCompare)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  // Identify where optlen is.
  const DeclRefExpr *LHSd = dyn_cast<DeclRefExpr>(LHS);
  const DeclRefExpr *RHSd = dyn_cast<DeclRefExpr>(RHS);

  bool LHSIsOptlen = false, RHSIsOptlen = false;
  if (LHSd) {
    if (const auto *PD = dyn_cast<ParmVarDecl>(LHSd->getDecl()))
      LHSIsOptlen = (PD == OptlenParm);
  }
  if (RHSd) {
    if (const auto *PD = dyn_cast<ParmVarDecl>(RHSd->getDecl()))
      RHSIsOptlen = (PD == OptlenParm);
  }
  if (!LHSIsOptlen && !RHSIsOptlen)
    return;

  // Evaluate the non-optlen side to a constant.
  uint64_t K = 0;
  const Expr *Other = LHSIsOptlen ? RHS : (RHSIsOptlen ? LHS : nullptr);
  if (!Other)
    return;
  if (!tryEvalToConst(Other, K, C))
    return;

  ProgramStateRef State = C.getState();
  SVal CondV = State->getSVal(CondE, C.getLocationContext());
  Optional<DefinedOrUnknownSVal> DV = CondV.getAs<DefinedOrUnknownSVal>();
  if (!DV)
    return;

  ProgramStateRef StTrue, StFalse;
  std::tie(StTrue, StFalse) = State->assume(*DV);

  // For each branch, compute LB updates based on the form of comparison.
  auto updateForBranch = [&](ProgramStateRef SIn, bool IsTrue) -> ProgramStateRef {
    if (!SIn)
      return nullptr;

    // Helper lambda to set LB.
    auto set = [&](uint64_t LB) -> ProgramStateRef {
      return setLB(SIn, OptlenParm, LB);
    };

    switch (Op) {
      case BO_LT:
        if (LHSIsOptlen) {
          // optlen < K
          // True: no LB. False: optlen >= K -> LB=K
          return IsTrue ? SIn : set(K);
        } else {
          // K < optlen
          // True: optlen > K -> LB=K+1; False: no LB
          return IsTrue ? set(K + 1) : SIn;
        }
      case BO_LE:
        if (LHSIsOptlen) {
          // optlen <= K
          // True: no LB; False: optlen > K -> LB=K+1
          return IsTrue ? SIn : set(K + 1);
        } else {
          // K <= optlen
          // True: optlen >= K -> LB=K; False: no LB
          return IsTrue ? set(K) : SIn;
        }
      case BO_GT:
        if (LHSIsOptlen) {
          // optlen > K
          // True: LB=K+1; False: no LB
          return IsTrue ? set(K + 1) : SIn;
        } else {
          // K > optlen
          // True: no LB; False: optlen >= K -> LB=K
          return IsTrue ? SIn : set(K);
        }
      case BO_GE:
        if (LHSIsOptlen) {
          // optlen >= K
          // True: LB=K; False: no LB
          return IsTrue ? set(K) : SIn;
        } else {
          // K >= optlen
          // True: no LB; False: optlen > K -> LB=K+1
          return IsTrue ? SIn : set(K + 1);
        }
      case BO_EQ:
        // optlen == K OR K == optlen
        // True: LB=K; False: no LB
        return IsTrue ? set(K) : SIn;
      default:
        break;
    }
    return SIn;
  };

  ProgramStateRef NT = updateForBranch(StTrue, /*IsTrue=*/true);
  ProgramStateRef NF = updateForBranch(StFalse, /*IsTrue=*/false);

  // Add transitions for the branches we refined. If neither updated, keep original.
  bool Added = false;
  if (NT && NT != StTrue) { C.addTransition(NT); Added = true; }
  if (NF && NF != StFalse) { C.addTransition(NF); Added = true; }
  if (!Added) {
    // No refinement possible; continue with current state.
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const auto *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(C.getState());
    return;
  }

  const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  const ParmVarDecl *OptlenParm = getOptlenParm(FD);
  if (!OptlenParm) {
    C.addTransition(C.getState());
    return;
  }

  processOptlenCompareBranch(CondE, OptlenParm, C);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Restrict to functions likely to be setsockopt handlers.
  const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD)
    return;
  if (!FD->getName().contains("setsockopt"))
    return;

  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return;

  // Safe helper: bt_copy_from_sockptr checks optlen internally.
  if (ExprHasName(OE, "bt_copy_from_sockptr", C))
    return;

  bool IsCopy = false;
  bool IsOffset = false;

  if (ExprHasName(OE, "copy_from_sockptr_offset", C)) {
    IsCopy = true;
    IsOffset = true;
  } else if (ExprHasName(OE, "copy_from_sockptr", C)) {
    IsCopy = true;
    IsOffset = false;
  }

  if (!IsCopy)
    return;

  // Confirm the source argument is optval (arg index 1).
  if (Call.getNumArgs() < (IsOffset ? 4u : 3u))
    return;

  const Expr *SrcArgE = Call.getArgExpr(1);
  if (!SrcArgE || !ExprHasName(SrcArgE, "optval", C))
    return;

  // Size argument index differs for offset variant.
  unsigned SizeIdx = IsOffset ? 3u : 2u;
  const Expr *SizeE = Call.getArgExpr(SizeIdx);
  if (!SizeE)
    return;

  uint64_t CopySize = 0;
  if (!tryEvalToConst(SizeE, CopySize, C))
    return; // Only consider fixed-sized copies.

  const ParmVarDecl *OptlenParm = getOptlenParm(FD);
  if (!OptlenParm)
    return;

  ProgramStateRef State = C.getState();
  uint64_t LB = 0;
  if (const uint64_t *KnownLB = State->get<OptlenLBMap>(OptlenParm))
    LB = *KnownLB;

  if (LB < CopySize) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "copy_from_sockptr with fixed size without checking optlen", N);
    R->addRange(Call.getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect blindly copying fixed size from sockptr without validating optlen",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
