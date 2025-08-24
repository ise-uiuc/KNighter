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
#include "clang/AST/Decl.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UntrustedLenMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
class SAGenTestChecker
  : public Checker<
      check::Bind,
      check::PreCall,
      check::BranchCondition
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unvalidated RSS length", "Memory Safety")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      static const Expr* getRHSOfStore(const Stmt *S);
      static const CallExpr* getAnyCallInStmt(const Stmt *S);
      static bool isVirtioCreadRssMaxKey(const CallExpr *CE, CheckerContext &C);
      static bool isMinOrClampWithMax(const CallExpr *CE, CheckerContext &C);
      static bool isLenAPICall(const Expr *Origin, StringRef &NameOut, unsigned &LenIdx, unsigned ArgCount);
      static bool isLenAPICandidate(const Expr *Origin, StringRef &NameOut, unsigned &LenIdx);

      static ProgramStateRef markChecked(ProgramStateRef State, const MemRegion *R);
      static ProgramStateRef copyStatusAndAlias(ProgramStateRef State,
                                                const MemRegion *DstR,
                                                const MemRegion *SrcR);
      static const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C);

      static void collectTrackedRegionsInExpr(const Expr *E, CheckerContext &C,
                                              ProgramStateRef State,
                                              llvm::SmallVectorImpl<const MemRegion*> &Out);
      void reportUnvalidatedUse(const CallEvent &Call, const Expr *ArgE, CheckerContext &C) const;
};

const Expr* SAGenTestChecker::getRHSOfStore(const Stmt *S) {
  if (!S) return nullptr;
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      return BO->getRHS();
  }
  if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    for (const auto *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (const Expr *Init = VD->getInit())
          return Init;
      }
    }
  }
  // Fallback: try to find any expression child
  if (const auto *E = dyn_cast<Expr>(S))
    return E;
  return nullptr;
}

const CallExpr* SAGenTestChecker::getAnyCallInStmt(const Stmt *S) {
  if (!S) return nullptr;
  return findSpecificTypeInChildren<const CallExpr>(S);
}

bool SAGenTestChecker::isVirtioCreadRssMaxKey(const CallExpr *CE, CheckerContext &C) {
  if (!CE) return false;
  const Expr *O = CE;
  // Match virtio_cread8/16/32 and the field rss_max_key_size in args.
  if (!(ExprHasName(O, "virtio_cread8", C) ||
        ExprHasName(O, "virtio_cread16", C) ||
        ExprHasName(O, "virtio_cread32", C) ||
        ExprHasName(O, "virtio_cread_bytes", C)))
    return false;

  if (!ExprHasName(O, "rss_max_key_size", C))
    return false;

  return true;
}

bool SAGenTestChecker::isMinOrClampWithMax(const CallExpr *CE, CheckerContext &C) {
  if (!CE) return false;
  const Expr *O = CE;
  if (!(ExprHasName(O, "min", C) ||
        ExprHasName(O, "min_t", C) ||
        ExprHasName(O, "clamp", C) ||
        ExprHasName(O, "clamp_t", C)))
    return false;

  // Must involve the maximum macro in any arg.
  for (const Expr *Arg : CE->arguments()) {
    if (ExprHasName(Arg, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLenAPICall(const Expr *Origin, StringRef &NameOut, unsigned &LenIdx, unsigned ArgCount) {
  if (!Origin) return false;

  // Length index for typical C memory functions: last parameter index = 2 for 3-arg functions.
  struct Entry { const char *Name; unsigned LenIndex; unsigned MinArgs; };
  static const Entry Table[] = {
    {"sg_init_one", 2, 3},
    {"sg_set_buf",  2, 3},
    {"memcpy",      2, 3},
    {"memmove",     2, 3},
    {"memset",      2, 3},
    {"memcpy_toio", 2, 3},
    {"memcpy_fromio", 2, 3},
    {"strncpy",     2, 3},
    {"strscpy",     2, 3},
  };

  for (const auto &E : Table) {
    if (ExprHasName(Origin, E.Name, *(const CheckerContext*)nullptr)) {
      // We cannot use CheckerContext here. The caller should verify with real Ctx if needed.
      (void)ArgCount; // origin check only
    }
  }
  // Since ExprHasName requires a CheckerContext, we move matching into isLenAPICandidate.
  return false;
}

bool SAGenTestChecker::isLenAPICandidate(const Expr *Origin, StringRef &NameOut, unsigned &LenIdx) {
  if (!Origin) return false;
  struct Entry { const char *Name; unsigned LenIndex; };
  static const Entry Table[] = {
    {"sg_init_one", 2},
    {"sg_set_buf",  2},
    {"memcpy",      2},
    {"memmove",     2},
    {"memset",      2},
    {"memcpy_toio", 2},
    {"memcpy_fromio", 2},
    {"strncpy",     2},
    {"strscpy",     2},
  };

  for (const auto &E : Table) {
    if (ExprHasName(Origin, E.Name, *(const CheckerContext*)nullptr)) {
      // This path won't work; provide a version using CheckerContext directly.
      (void)E;
    }
  }
  // Proper implementation with CheckerContext is below in checkPreCall directly.
  return false;
}

ProgramStateRef SAGenTestChecker::markChecked(ProgramStateRef State, const MemRegion *R) {
  if (!R) return State;
  const MemRegion *Base = R->getBaseRegion();
  if (!Base) return State;

  const bool *Tracked = State->get<UntrustedLenMap>(Base);
  if (Tracked && *Tracked == false) {
    State = State->set<UntrustedLenMap>(Base, true);
  }

  // If we have an alias, mark it checked too.
  if (const MemRegion *Alias = State->get<PtrAliasMap>(Base)) {
    const bool *AliasTracked = State->get<UntrustedLenMap>(Alias);
    if (AliasTracked && *AliasTracked == false) {
      State = State->set<UntrustedLenMap>(Alias, true);
    }
  }
  return State;
}

ProgramStateRef SAGenTestChecker::copyStatusAndAlias(ProgramStateRef State,
                                                     const MemRegion *DstR,
                                                     const MemRegion *SrcR) {
  if (!DstR || !SrcR) return State;
  DstR = DstR->getBaseRegion();
  SrcR = SrcR->getBaseRegion();
  if (!DstR || !SrcR) return State;

  // Copy status if any
  if (const bool *Tracked = State->get<UntrustedLenMap>(SrcR)) {
    State = State->set<UntrustedLenMap>(DstR, *Tracked);
  }
  // Record alias both ways
  State = State->set<PtrAliasMap>(DstR, SrcR);
  State = State->set<PtrAliasMap>(SrcR, DstR);

  return State;
}

const MemRegion* SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

void SAGenTestChecker::collectTrackedRegionsInExpr(const Expr *E, CheckerContext &C,
                                                   ProgramStateRef State,
                                                   llvm::SmallVectorImpl<const MemRegion*> &Out) {
  if (!E) return;
  // Try current node
  if (const MemRegion *MR = getMemRegionFromExpr(E, C)) {
    MR = MR->getBaseRegion();
    if (MR) {
      if (const bool *Tracked = State->get<UntrustedLenMap>(MR)) {
        if (*Tracked == false) {
          Out.push_back(MR);
        }
      }
    }
  }
  // Recurse into children
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child)) {
      collectTrackedRegionsInExpr(CE, C, State, Out);
    }
  }
}

void SAGenTestChecker::reportUnvalidatedUse(const CallEvent &Call, const Expr *ArgE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unvalidated device length used for buffer size (RSS key)", N);
  if (ArgE)
    R->addRange(ArgE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstR = Loc.getAsRegion();
  if (!DstR) return;
  DstR = DstR->getBaseRegion();
  if (!DstR) return;

  bool StateChanged = false;
  const Expr *RHS = getRHSOfStore(StoreE);

  // 1) Detect assignment from virtio_cread* reading rss_max_key_size
  if (const CallExpr *CE = getAnyCallInStmt(StoreE)) {
    if (isVirtioCreadRssMaxKey(CE, C)) {
      // Mark destination as untrusted/unchecked.
      State = State->set<UntrustedLenMap>(DstR, false);
      StateChanged = true;
      // Clear any previous alias pointing somewhere irrelevant
      // We don't remove here; keep simple.
    } else if (isMinOrClampWithMax(CE, C)) {
      // If this is min/clamp involving the macro, and one operand is tracked,
      // mark DstR as checked.
      // Check if any arg is tracked
      bool TrackedOperand = false;
      for (const Expr *Arg : CE->arguments()) {
        const MemRegion *OpR = getBaseRegionFromExpr(Arg, C);
        if (!OpR) continue;
        if (const bool *Tracked = State->get<UntrustedLenMap>(OpR)) {
          if (*Tracked == false) {
            TrackedOperand = true;
            break;
          }
        }
      }
      if (TrackedOperand) {
        State = State->set<UntrustedLenMap>(DstR, true);
        StateChanged = true;
      }
    }
  }

  // 2) Alias/status propagation for simple copies (len = vi->rss_key_size;)
  if (RHS && !StateChanged) {
    if (const MemRegion *SrcR = getBaseRegionFromExpr(RHS, C)) {
      const bool *Tracked = State->get<UntrustedLenMap>(SrcR);
      if (Tracked) {
        State = copyStatusAndAlias(State, DstR, SrcR);
        StateChanged = true;
      }
    }
  }

  // 3) Overwrite handling: if DstR was tracked but RHS isn't from device or alias,
  //    then remove DstR from tracking.
  if (!StateChanged) {
    if (const bool *WasTracked = State->get<UntrustedLenMap>(DstR)) {
      (void)WasTracked;
      // Remove from UntrustedLenMap and alias map
      if (const MemRegion *Alias = State->get<PtrAliasMap>(DstR)) {
        State = State->remove<PtrAliasMap>(Alias);
      }
      State = State->remove<PtrAliasMap>(DstR);
      State = State->remove<UntrustedLenMap>(DstR);
      StateChanged = true;
    }
  }

  if (StateChanged)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  // Only care when the condition involves the macro VIRTIO_NET_RSS_MAX_KEY_SIZE
  if (!ExprHasName(CondE, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C)) {
    C.addTransition(State);
    return;
  }

  // Collect tracked regions referenced in this condition and mark them checked.
  llvm::SmallVector<const MemRegion*, 4> Regions;
  collectTrackedRegionsInExpr(CondE, C, State, Regions);

  bool Changed = false;
  for (const MemRegion *R : Regions) {
    ProgramStateRef NewState = markChecked(State, R);
    if (NewState != State) {
      State = NewState;
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
  else
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Identify candidate functions and their 'length' argument index.
  // Use ExprHasName for robustness as suggested.
  unsigned LenIdx = UINT_MAX;
  if (ExprHasName(Origin, "sg_init_one", C)) {
    if (Call.getNumArgs() >= 3) LenIdx = 2;
  } else if (ExprHasName(Origin, "sg_set_buf", C)) {
    if (Call.getNumArgs() >= 3) LenIdx = 2;
  } else if (ExprHasName(Origin, "memcpy", C) ||
             ExprHasName(Origin, "memmove", C) ||
             ExprHasName(Origin, "memset", C) ||
             ExprHasName(Origin, "memcpy_toio", C) ||
             ExprHasName(Origin, "memcpy_fromio", C) ||
             ExprHasName(Origin, "strncpy", C) ||
             ExprHasName(Origin, "strscpy", C)) {
    if (Call.getNumArgs() >= 3) LenIdx = 2;
  } else {
    return;
  }

  if (LenIdx == UINT_MAX || LenIdx >= Call.getNumArgs())
    return;

  const Expr *ArgE = Call.getArgExpr(LenIdx);
  if (!ArgE)
    return;

  ProgramStateRef State = C.getState();

  // First, check by region
  const MemRegion *LenR = getBaseRegionFromExpr(ArgE, C);
  if (LenR) {
    if (const bool *Tracked = State->get<UntrustedLenMap>(LenR)) {
      if (*Tracked == false) {
        reportUnvalidatedUse(Call, ArgE, C);
        return;
      }
    }
    // Alias fallback
    if (const MemRegion *Alias = State->get<PtrAliasMap>(LenR)) {
      if (const bool *AliasTracked = State->get<UntrustedLenMap>(Alias)) {
        if (*AliasTracked == false) {
          reportUnvalidatedUse(Call, ArgE, C);
          return;
        }
      }
    }
  }

  // Textual fallback: if the expression contains rss_key_size, but we don't
  // have region info, do not report unless we are certain; per suggestion,
  // avoid reporting if unsure. So we skip here.
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of unvalidated device-provided RSS length for buffer sizing",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
