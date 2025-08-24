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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track variables that currently hold the return value of a known "set_ready" call.
// Map: VarRegion -> Resource pattern index (unsigned).
REGISTER_MAP_WITH_PROGRAMSTATE(ReadyErrVarMap, const MemRegion *, unsigned)

namespace {

// Knowledge base for the target pattern.
struct ResourcePattern {
  const char *ReadySetter;
  const char *const *CompositeCloses;   // functions that close/free too much (bad here)
  unsigned NumCompositeCloses;
  const char *const *AllowedDestroys;   // correct functions to call in error path
  unsigned NumAllowedDestroys;
};

// Pattern 0: mlx5 SQ ready/set + close/destroy names.
static const char *const Pattern0CompositeCloses[] = {
  "hws_send_ring_close_sq"
};
static const char *const Pattern0AllowedDestroys[] = {
  "mlx5_core_destroy_sq",
  "hws_send_ring_destroy_sq"
};
static const ResourcePattern Patterns[] = {
  {
    "hws_send_ring_set_sq_rdy",
    Pattern0CompositeCloses, sizeof(Pattern0CompositeCloses) / sizeof(const char *),
    Pattern0AllowedDestroys, sizeof(Pattern0AllowedDestroys) / sizeof(const char *)
  }
};
static constexpr unsigned NumPatterns = sizeof(Patterns) / sizeof(ResourcePattern);

// Helper: extract direct callee name if possible.
static StringRef getDirectCalleeName(const CallExpr *CE) {
  if (!CE)
    return StringRef();
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (const IdentifierInfo *II = FD->getIdentifier())
      return II->getName();
  }
  return StringRef();
}

// Helper: Does CE match any of the provided names? Prefer direct name, fallback to source-text search via ExprHasName.
static bool callMatchesAny(const CallExpr *CE, ArrayRef<const char *> Names, CheckerContext &C) {
  StringRef DirectName = getDirectCalleeName(CE);
  if (!DirectName.empty()) {
    for (const char *N : Names) {
      if (DirectName.equals(N))
        return true;
    }
  }
  for (const char *N : Names) {
    if (ExprHasName(CE, N, C))
      return true;
  }
  return false;
}

static int findReadySetterIndexByName(StringRef Name) {
  for (unsigned i = 0; i < NumPatterns; ++i) {
    if (Name.equals(Patterns[i].ReadySetter))
      return static_cast<int>(i);
  }
  return -1;
}

static int findReadySetterIndexByCall(const CallExpr *CE, CheckerContext &C) {
  // First try direct callee name.
  StringRef Direct = getDirectCalleeName(CE);
  if (!Direct.empty()) {
    int Idx = findReadySetterIndexByName(Direct);
    if (Idx >= 0)
      return Idx;
  }
  // Fallback: check by ExprHasName against all patterns.
  for (unsigned i = 0; i < NumPatterns; ++i) {
    if (ExprHasName(CE, Patterns[i].ReadySetter, C))
      return static_cast<int>(i);
  }
  return -1;
}

static bool isCompositeCloseCall(unsigned Idx, const CallExpr *CE, CheckerContext &C) {
  if (Idx >= NumPatterns) return false;
  ArrayRef<const char *> Names(Patterns[Idx].CompositeCloses, Patterns[Idx].NumCompositeCloses);
  return callMatchesAny(CE, Names, C);
}

static bool isAllowedDestroyCall(unsigned Idx, const CallExpr *CE, CheckerContext &C) {
  if (Idx >= NumPatterns) return false;
  ArrayRef<const char *> Names(Patterns[Idx].AllowedDestroys, Patterns[Idx].NumAllowedDestroys);
  return callMatchesAny(CE, Names, C);
}

// Collect all CallExpr nodes under a given statement.
struct CallCollector : public RecursiveASTVisitor<CallCollector> {
  llvm::SmallVector<const CallExpr *, 16> Calls;
  bool VisitCallExpr(const CallExpr *CE) {
    Calls.push_back(CE);
    return true;
  }
};

static void collectCallExprs(const Stmt *S, llvm::SmallVectorImpl<const CallExpr *> &Out) {
  if (!S) return;
  CallCollector V;
  // TraverseStmt expects non-const pointer, cast away const for traversal only.
  V.TraverseStmt(const_cast<Stmt *>(S));
  Out.append(V.Calls.begin(), V.Calls.end());
}

class SAGenTestChecker : public Checker<check::Bind, check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Composite close in set_ready() error path", "Resource Management")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      void reportCompositeClose(const CallExpr *BadCall, CheckerContext &C) const;
};

void SAGenTestChecker::reportCompositeClose(const CallExpr *BadCall, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Composite close in set_ready() error path; call destroy() to avoid double free.", N);
  if (BadCall)
    R->addRange(BadCall->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  ProgramStateRef State = C.getState();

  // Get LHS region from the store location.
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  // Ensure it's a typed variable region with integral type (like "int err").
  const auto *TVR = dyn_cast<TypedValueRegion>(LHSReg);
  if (!TVR)
    return;
  QualType LTy = TVR->getValueType();
  if (LTy.isNull() || !LTy->isIntegerType())
    return;

  // Attempt to find a CallExpr on the RHS within this statement.
  const CallExpr *RHSCall = findSpecificTypeInChildren<CallExpr>(S);
  if (!RHSCall) {
    // No call on RHS; clear any previous mapping for this variable.
    State = State->remove<ReadyErrVarMap>(LHSReg);
    C.addTransition(State);
    return;
  }

  // Determine if this is a known ReadySetter call.
  int Idx = findReadySetterIndexByCall(RHSCall, C);
  if (Idx >= 0) {
    State = State->set<ReadyErrVarMap>(LHSReg, static_cast<unsigned>(Idx));
  } else {
    State = State->remove<ReadyErrVarMap>(LHSReg);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  ProgramStateRef State = C.getState();

  // Step A: Determine if condition checks a known set_ready() failure.

  // Case A1: inline call in condition.
  unsigned Idx = static_cast<unsigned>(-1);
  bool FromVar = false;
  const MemRegion *CondVarReg = nullptr;

  const CallExpr *CondCall = findSpecificTypeInChildren<CallExpr>(Condition);
  if (CondCall) {
    int Tmp = findReadySetterIndexByCall(CondCall, C);
    if (Tmp >= 0)
      Idx = static_cast<unsigned>(Tmp);
  }

  // Case A2: variable in condition (err, err != 0, err < 0, etc.).
  if (Idx == static_cast<unsigned>(-1)) {
    const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(Condition);
    if (DRE) {
      const MemRegion *MR = getMemRegionFromExpr(DRE, C);
      if (MR) {
        MR = MR->getBaseRegion();
        if (MR) {
          if (const unsigned *SavedIdx = State->get<ReadyErrVarMap>(MR)) {
            Idx = *SavedIdx;
            FromVar = true;
            CondVarReg = MR;
          }
        }
      }
    }
  }

  if (Idx == static_cast<unsigned>(-1))
    return; // Not a set_ready guarded condition.

  // Step B: Find the containing IfStmt and its then-branch.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Stmt *Then = IS->getThen();
  if (!Then)
    return;

  // Step C: Search the then-body for a composite close call.
  llvm::SmallVector<const CallExpr *, 16> Calls;
  collectCallExprs(Then, Calls);

  for (const CallExpr *CE : Calls) {
    if (isCompositeCloseCall(Idx, CE, C)) {
      // Found the problematic composite close call.
      reportCompositeClose(CE, C);
      break;
    }
  }

  // Step D: Cleanup transient mapping for condition variable if used.
  if (FromVar && CondVarReg) {
    State = State->remove<ReadyErrVarMap>(CondVarReg);
    C.addTransition(State);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects composite close/cleanup in set_ready() error path which may cause double free; use destroy()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
