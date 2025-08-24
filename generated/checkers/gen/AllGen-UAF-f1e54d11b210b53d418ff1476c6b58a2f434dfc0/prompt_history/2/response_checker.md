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
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
// - PtrAliasMap: tracks aliasing between pointer-holding regions (LHS region -> RHS root region)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
// - DstCarrierMap: marks that a metadata_dst pointer has been used as a dst carrier (&p->dst passed to dst APIs)
REGISTER_MAP_WITH_PROGRAMSTATE(DstCarrierMap, const MemRegion*, bool)
// - DstHoldCountMap: best-effort counter of dst_hold/dst_release per pointer region
REGISTER_MAP_WITH_PROGRAMSTATE(DstHoldCountMap, const MemRegion*, unsigned)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Freeing refcounted metadata_dst directly", "Reference counting")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:

      // Helper: follow alias map to get a canonical root region
      const MemRegion *getRootRegion(const MemRegion *R, ProgramStateRef State) const {
        if (!R) return nullptr;
        const MemRegion *Cur = R->getBaseRegion();
        // Follow aliases until fixed point (with a hard iteration cap to prevent cycles)
        for (unsigned i = 0; i < 16; ++i) {
          const MemRegion *const *Next = State->get<PtrAliasMap>(Cur);
          if (!Next)
            break;
          const MemRegion *NextBase = (*Next) ? (*Next)->getBaseRegion() : nullptr;
          if (!NextBase || NextBase == Cur)
            break;
          Cur = NextBase;
        }
        return Cur;
      }

      // Helper: check if Arg is of form &X->dst or &X.dst, and return base X in OutBaseExpr
      bool isMemberAddrOfDst(const Expr *Arg, const Expr *&OutBaseExpr) const {
        OutBaseExpr = nullptr;
        if (!Arg)
          return false;
        const Expr *E = Arg->IgnoreParenCasts();
        const auto *UO = dyn_cast<UnaryOperator>(E);
        if (!UO || UO->getOpcode() != UO_AddrOf)
          return false;

        const Expr *Sub = UO->getSubExpr();
        if (!Sub)
          return false;
        Sub = Sub->IgnoreParenCasts();

        const auto *ME = dyn_cast<MemberExpr>(Sub);
        if (!ME)
          return false;

        const ValueDecl *VD = ME->getMemberDecl();
        if (!VD || !VD->getIdentifier())
          return false;

        if (VD->getName() != "dst")
          return false;

        OutBaseExpr = ME->getBase();
        return OutBaseExpr != nullptr;
      }

      // Helper: get pointee region from an expression using provided utility
      const MemRegion *getRegionFromExprPointee(const Expr *E, CheckerContext &C) const {
        if (!E) return nullptr;
        const MemRegion *MR = getMemRegionFromExpr(E, C);
        if (!MR) return nullptr;
        return MR->getBaseRegion();
      }

      // Helper: robust callee-name check using provided utility
      bool isCallNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const {
        const Expr *Origin = Call.getOriginExpr();
        if (!Origin) return false;
        return ExprHasName(Origin, Name, C);
      }

      void reportFreeOfDstCarrier(const CallEvent &Call, CheckerContext &C) const {
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N) return;
        auto R = std::make_unique<PathSensitiveBugReport>(
            *BT, "Freeing metadata_dst directly; use dst_release(&p->dst)", N);
        R->addRange(Call.getSourceRange());
        C.emitReport(std::move(R));
      }
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return;

  // Recognize core dst APIs
  bool IsDstHold = isCallNamed(Call, C, "dst_hold");
  bool IsDstRelease = isCallNamed(Call, C, "dst_release");
  bool IsSkbDstSet = isCallNamed(Call, C, "skb_dst_set");

  bool IsMetaDstFree = isCallNamed(Call, C, "metadata_dst_free");
  bool IsKfree = isCallNamed(Call, C, "kfree");

  // dst_hold/dst_release: argument 0 is &p->dst
  if (IsDstHold || IsDstRelease) {
    if (Call.getNumArgs() >= 1) {
      const Expr *BaseExpr = nullptr;
      if (isMemberAddrOfDst(Call.getArgExpr(0), BaseExpr)) {
        const MemRegion *MR = getRegionFromExprPointee(BaseExpr, C);
        if (MR) {
          const MemRegion *Root = getRootRegion(MR, State);
          if (Root) {
            // Mark as carrier
            State = State->set<DstCarrierMap>(Root, true);
            // Update hold count
            unsigned Count = 0;
            if (const unsigned *PC = State->get<DstHoldCountMap>(Root))
              Count = *PC;
            if (IsDstHold) {
              State = State->set<DstHoldCountMap>(Root, Count + 1);
            } else { // IsDstRelease
              if (Count > 0)
                State = State->set<DstHoldCountMap>(Root, Count - 1);
              else
                State = State->set<DstHoldCountMap>(Root, 0u);
            }
          }
        }
      }
    }
    C.addTransition(State);
    return;
  }

  // skb_dst_set(skb, &p->dst) : argument 1
  if (IsSkbDstSet) {
    if (Call.getNumArgs() >= 2) {
      const Expr *BaseExpr = nullptr;
      if (isMemberAddrOfDst(Call.getArgExpr(1), BaseExpr)) {
        const MemRegion *MR = getRegionFromExprPointee(BaseExpr, C);
        if (MR) {
          const MemRegion *Root = getRootRegion(MR, State);
          if (Root) {
            State = State->set<DstCarrierMap>(Root, true);
          }
        }
      }
    }
    C.addTransition(State);
    return;
  }

  // metadata_dst_free(p) or kfree(p) : check if p is a known dst-carrier
  if (IsMetaDstFree || IsKfree) {
    if (Call.getNumArgs() >= 1) {
      const Expr *ArgE = Call.getArgExpr(0);
      const MemRegion *MR = getRegionFromExprPointee(ArgE, C);
      if (MR) {
        const MemRegion *Root = getRootRegion(MR, State);
        if (Root) {
          const bool *IsCarrier = State->get<DstCarrierMap>(Root);
          if (IsCarrier && *IsCarrier) {
            reportFreeOfDstCarrier(Call, C);
            return;
          }
        }
      }

      // Fallback heuristic to catch the shown buggy code (macsec md_dst):
      // If the expression clearly refers to "md_dst" or "metadata_dst",
      // warn as direct free is unsafe; the correct API is dst_release(&p->dst).
      if (ArgE && (ExprHasName(ArgE, "md_dst", C) || ExprHasName(ArgE, "metadata_dst", C))) {
        reportFreeOfDstCarrier(Call, C);
        return;
      }
    }
    C.addTransition(State);
    return;
  }

  // Default transition
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }

  const MemRegion *RHSReg = Val.getAsRegion();
  if (RHSReg) {
    RHSReg = RHSReg->getBaseRegion();
    if (RHSReg) {
      const MemRegion *RootRHS = getRootRegion(RHSReg, State);
      if (!RootRHS) RootRHS = RHSReg;
      // Record alias both ways to improve canonicalization
      State = State->set<PtrAliasMap>(LHSReg, RootRHS);
      State = State->set<PtrAliasMap>(RootRHS, LHSReg);
    }
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing metadata_dst directly instead of dropping reference via dst_release",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
