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
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Store.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/DenseSet.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion*, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

enum PerCpuKind : unsigned {
  PCPU_Unknown = 0,
  PCPU_LocalThisCPU = 1,  // Derived from this_cpu_ptr(...) or per_cpu_ptr(..., smp_processor_id())
  PCPU_RemoteCPU = 2      // Derived from per_cpu_ptr(..., cpu) with explicit CPU not this CPU
};

class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::PostStmt<DeclStmt>,
        check::PreStmt<BinaryOperator>,
        check::PreStmt<CompoundAssignOperator>,
        check::PreStmt<UnaryOperator>
      > {
   mutable std::unique_ptr<BugType> BT;
   // Avoid duplicate reports for the same statement.
   mutable llvm::DenseSet<const Stmt*> Reported;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Per-CPU data race", "Concurrency")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
      void checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const;
      void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;

   private:
      // Helpers
      static const MemRegion* baseRegionOfExpr(const Expr *E, CheckerContext &C);
      static const MemRegion* resolveAlias(const MemRegion *R, ProgramStateRef State);
      static bool isCallNamed(const CallExpr *CE, StringRef Name, CheckerContext &C);
      static bool isLocalCPUExpr(const Expr *E, CheckerContext &C);
      static unsigned classifyPerCpuCall(const CallExpr *CE, CheckerContext &C);
      static bool insideREADorWRITE_ONCE(const Expr *Child, CheckerContext &C);

      static const Expr* getRHSFromStore(const Stmt *StoreE, const MemRegion *LReg, CheckerContext &C);
      static const Expr* stripCasts(const Expr *E) {
        return E ? E->IgnoreParenCasts() : nullptr;
      }
      unsigned getClassFromMemberBase(const Expr *Base, CheckerContext &C) const;

      void setClassification(ProgramStateRef &State, const MemRegion *R, unsigned Kind) const;
      std::optional<unsigned> getClassification(ProgramStateRef State, const MemRegion *R) const;

      void trackAlias(ProgramStateRef &State, const MemRegion *A, const MemRegion *B) const;

      void reportIfNeeded(const Stmt *S, StringRef Msg, CheckerContext &C) const;
};

const MemRegion* SAGenTestChecker::baseRegionOfExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

const MemRegion* SAGenTestChecker::resolveAlias(const MemRegion *R, ProgramStateRef State) {
  if (!R) return nullptr;
  // Follow simple alias chains, with a small limit to avoid cycles.
  const MemRegion *Cur = R;
  for (int i = 0; i < 8; ++i) {
    const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Cur);
    if (!NextPtr) break;
    const MemRegion *Next = *NextPtr;
    if (!Next || Next == Cur) break;
    Cur = Next;
  }
  return Cur;
}

bool SAGenTestChecker::isCallNamed(const CallExpr *CE, StringRef Name, CheckerContext &C) {
  if (!CE) return false;
  const Expr *CalleeE = CE->getCallee();
  if (!CalleeE) return false;
  return ExprHasName(CalleeE, Name, C);
}

bool SAGenTestChecker::isLocalCPUExpr(const Expr *E, CheckerContext &C) {
  E = stripCasts(E);
  const CallExpr *CE = dyn_cast_or_null<CallExpr>(E);
  if (!CE) return false;
  // smp_processor_id() or raw_smp_processor_id()
  if (isCallNamed(CE, "smp_processor_id", C)) return true;
  if (isCallNamed(CE, "raw_smp_processor_id", C)) return true;
  return false;
}

unsigned SAGenTestChecker::classifyPerCpuCall(const CallExpr *CE, CheckerContext &C) {
  if (!CE) return PCPU_Unknown;
  if (isCallNamed(CE, "this_cpu_ptr", C))
    return PCPU_LocalThisCPU;

  if (isCallNamed(CE, "per_cpu_ptr", C)) {
    // per_cpu_ptr(ptr, cpu)
    if (CE->getNumArgs() >= 2) {
      const Expr *CPUArg = stripCasts(CE->getArg(1));
      if (isLocalCPUExpr(CPUArg, C))
        return PCPU_LocalThisCPU;
      return PCPU_RemoteCPU;
    }
  }
  return PCPU_Unknown;
}

bool SAGenTestChecker::insideREADorWRITE_ONCE(const Expr *Child, CheckerContext &C) {
  if (!Child) return false;
  const CallExpr *ParentCall = findSpecificTypeInParents<CallExpr>(Child, C);
  if (!ParentCall) return false;
  if (isCallNamed(ParentCall, "READ_ONCE", C)) return true;
  if (isCallNamed(ParentCall, "WRITE_ONCE", C)) return true;
  return false;
}

const Expr* SAGenTestChecker::getRHSFromStore(const Stmt *StoreE, const MemRegion *LReg, CheckerContext &C) {
  if (!StoreE) return nullptr;

  if (const auto *BO = dyn_cast<BinaryOperator>(StoreE)) {
    if (BO->isAssignmentOp())
      return stripCasts(BO->getRHS());
  }

  if (const auto *DS = dyn_cast<DeclStmt>(StoreE)) {
    for (const Decl *D : DS->decls()) {
      const auto *VD = dyn_cast<VarDecl>(D);
      if (!VD) continue;
      if (!VD->hasInit()) continue;

      // Match the specific variable bound in this bind via its region.
      MemRegionManager &MRMgr = C.getStoreManager().getRegionManager();
      const VarRegion *VRVar = MRMgr.getVarRegion(VD, C.getLocationContext());
      const MemRegion *VR = VRVar ? VRVar->getBaseRegion() : nullptr;
      if (!VR) continue;
      if (VR == LReg)
        return stripCasts(VD->getInit());
    }
  }

  // As a fallback, if StoreE is an Expr, just return it (best-effort).
  if (const auto *E = dyn_cast<Expr>(StoreE))
    return stripCasts(E);

  return nullptr;
}

unsigned SAGenTestChecker::getClassFromMemberBase(const Expr *Base, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  Base = stripCasts(Base);

  if (const auto *CE = dyn_cast<CallExpr>(Base)) {
    return classifyPerCpuCall(CE, C);
  }

  const MemRegion *BR = baseRegionOfExpr(Base, C);
  if (!BR) return PCPU_Unknown;
  BR = resolveAlias(BR, State);
  const unsigned *K = State->get<PerCpuPtrMap>(BR);
  return K ? *K : PCPU_Unknown;
}

void SAGenTestChecker::setClassification(ProgramStateRef &State, const MemRegion *R, unsigned Kind) const {
  if (!R || Kind == PCPU_Unknown) return;
  const unsigned *Old = State->get<PerCpuPtrMap>(R);
  if (!Old || *Old != Kind) {
    State = State->set<PerCpuPtrMap>(R, Kind);
  }
}

std::optional<unsigned> SAGenTestChecker::getClassification(ProgramStateRef State, const MemRegion *R) const {
  if (!R) return std::nullopt;
  const unsigned *K = State->get<PerCpuPtrMap>(R);
  if (!K) return std::nullopt;
  return *K;
}

void SAGenTestChecker::trackAlias(ProgramStateRef &State, const MemRegion *A, const MemRegion *B) const {
  if (!A || !B) return;
  State = State->set<PtrAliasMap>(A, B);
  State = State->set<PtrAliasMap>(B, A);
}

void SAGenTestChecker::reportIfNeeded(const Stmt *S, StringRef Msg, CheckerContext &C) const {
  if (!S) return;
  if (Reported.count(S)) return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
  Reported.insert(S);
}

// Track pointer origins and aliases.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LReg = Loc.getAsRegion();
  if (!LReg) return;
  LReg = LReg->getBaseRegion();
  if (!LReg) return;

  const Expr *RHS = getRHSFromStore(S, LReg, C);
  if (!RHS) return;

  RHS = stripCasts(RHS);

  bool Changed = false;

  // Case 1: RHS is a (this_cpu_ptr/per_cpu_ptr) call
  if (const auto *CE = dyn_cast<CallExpr>(RHS)) {
    unsigned Kind = classifyPerCpuCall(CE, C);
    if (Kind != PCPU_Unknown) {
      setClassification(State, LReg, Kind);
      Changed = true;
    }
  }

  // Case 2: RHS is a DeclRefExpr to another pointer; propagate classification and alias
  if (const auto *DRE = dyn_cast<DeclRefExpr>(RHS)) {
    const MemRegion *RReg = baseRegionOfExpr(DRE, C);
    if (RReg) {
      RReg = resolveAlias(RReg, State);
      if (auto K = getClassification(State, RReg)) {
        setClassification(State, LReg, *K);
        Changed = true;
      }
      trackAlias(State, LReg, RReg);
      Changed = true;
    }
  }

  // Case 3: RHS is a MemberExpr like "statc->parent"; propagate base classification
  if (const auto *ME = dyn_cast<MemberExpr>(RHS)) {
    unsigned K = getClassFromMemberBase(ME->getBase(), C);
    if (K != PCPU_Unknown) {
      setClassification(State, LReg, K);
      Changed = true;
    }
    // Do not alias LReg with ME base; they are different addresses.
  }

  if (Changed)
    C.addTransition(State);
}

// Handle VarDecl initializers (e.g., struct *statc = per_cpu_ptr(...);)
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD || !VD->hasInit())
      continue;

    const Expr *Init = stripCasts(VD->getInit());
    if (!Init) continue;

    MemRegionManager &MRMgr = C.getStoreManager().getRegionManager();
    const VarRegion *VRVar = MRMgr.getVarRegion(VD, C.getLocationContext());
    const MemRegion *LReg = VRVar ? VRVar->getBaseRegion() : nullptr;
    if (!LReg) continue;

    // Classify per_cpu calls
    if (const auto *CE = dyn_cast<CallExpr>(Init)) {
      unsigned Kind = classifyPerCpuCall(CE, C);
      if (Kind != PCPU_Unknown) {
        setClassification(State, LReg, Kind);
        Changed = true;
      }
    } else if (const auto *DRE = dyn_cast<DeclRefExpr>(Init)) {
      // Propagate from another var
      const MemRegion *RReg = baseRegionOfExpr(DRE, C);
      if (RReg) {
        RReg = resolveAlias(RReg, State);
        if (auto K = getClassification(State, RReg)) {
          setClassification(State, LReg, *K);
          Changed = true;
        }
        trackAlias(State, LReg, RReg);
        Changed = true;
      }
    } else if (const auto *ME = dyn_cast<MemberExpr>(Init)) {
      unsigned K = getClassFromMemberBase(ME->getBase(), C);
      if (K != PCPU_Unknown) {
        setClassification(State, LReg, K);
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

// Detect remote write: statc->stats_updates = ...
void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
  if (!BO->isAssignmentOp())
    return;

  const Expr *LHS = stripCasts(BO->getLHS());
  if (!LHS) return;

  const auto *ME = dyn_cast<MemberExpr>(LHS);
  if (!ME) return;

  // If already protected by READ/WRITE_ONCE, skip.
  if (insideREADorWRITE_ONCE(ME, C))
    return;

  unsigned Kind = getClassFromMemberBase(ME->getBase(), C);
  if (Kind == PCPU_RemoteCPU) {
    reportIfNeeded(BO, "Remote per-CPU field write without WRITE_ONCE", C);
  }
  // For local plain assignment we do not warn (RMW is handled below).
}

// Detect local/remote RMW: "+=", "-="
void SAGenTestChecker::checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const {
  const Expr *LHS = stripCasts(CAO->getLHS());
  if (!LHS) return;

  const auto *ME = dyn_cast<MemberExpr>(LHS);
  if (!ME) return;

  if (insideREADorWRITE_ONCE(ME, C))
    return;

  unsigned Kind = getClassFromMemberBase(ME->getBase(), C);
  if (Kind == PCPU_LocalThisCPU || Kind == PCPU_RemoteCPU) {
    reportIfNeeded(CAO, "RMW on per-CPU field without READ_ONCE/WRITE_ONCE", C);
  }
}

// Detect ++/-- on per-CPU fields
void SAGenTestChecker::checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const {
  UnaryOperatorKind Op = UO->getOpcode();
  if (Op != UO_PreInc && Op != UO_PostInc && Op != UO_PreDec && Op != UO_PostDec)
    return;

  const Expr *Sub = stripCasts(UO->getSubExpr());
  if (!Sub) return;

  const auto *ME = dyn_cast<MemberExpr>(Sub);
  if (!ME) return;

  if (insideREADorWRITE_ONCE(ME, C))
    return;

  unsigned Kind = getClassFromMemberBase(ME->getBase(), C);
  if (Kind == PCPU_LocalThisCPU || Kind == PCPU_RemoteCPU) {
    reportIfNeeded(UO, "RMW on per-CPU field without READ_ONCE/WRITE_ONCE", C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsynchronized RMW and remote writes on per-CPU fields lacking READ_ONCE/WRITE_ONCE",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
