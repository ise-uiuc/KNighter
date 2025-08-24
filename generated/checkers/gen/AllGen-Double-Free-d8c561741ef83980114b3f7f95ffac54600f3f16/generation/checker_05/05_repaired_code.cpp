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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/Support/Casting.h"
#include "llvm/ADT/ImmutableMap.h"
#include <string>
#include <cctype>
#include <memory>

namespace clang {
namespace ento {

using namespace taint;

// ------------ Program state ------------

struct ResourceInfo {
  unsigned Step;                // 0 = none, 1 = HW created
  const char *ExpectedDestroy;  // expected HW-only destroy function name (literal)
  bool IsParamOwned;            // resource is owned by caller (argument/parameter)

  ResourceInfo() : Step(0), ExpectedDestroy(nullptr), IsParamOwned(false) {}
  ResourceInfo(unsigned S, const char *ED, bool P)
      : Step(S), ExpectedDestroy(ED), IsParamOwned(P) {}

  // Required by ProgramState map storage.
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(Step);
    ID.AddPointer(ExpectedDestroy);
    ID.AddInteger(static_cast<unsigned>(IsParamOwned));
  }

  bool operator==(const ResourceInfo &Other) const {
    return Step == Other.Step &&
           ExpectedDestroy == Other.ExpectedDestroy &&
           IsParamOwned == Other.IsParamOwned;
  }
};

// Program state trait for tracking resources.
namespace {
struct ResourceInfoMap {};
using ResourceInfoMapTy = llvm::ImmutableMap<const MemRegion *, ResourceInfo>;
} // end anonymous namespace

template <>
struct ProgramStateTrait<ResourceInfoMap>
    : public ProgramStatePartialTrait<ResourceInfoMapTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

// ------------ Helper tables ------------

struct CreateDestroyPair {
  const char *CreateName;
  const char *DestroyName;
  unsigned ResourceArgIndex; // index of resource arg in create call
};

// We cover both the low-level core create and the wrapper create helper.
static const CreateDestroyPair KnownPairs[] = {
  // mlx5_core_create_sq(dev, in, inlen, &sq->sqn)
  { "mlx5_core_create_sq", "mlx5_core_destroy_sq", 3 },
  // hws_send_ring_create_sq(mdev, pdn, sqc_data, queue, sq, cq)
  { "hws_send_ring_create_sq", "mlx5_core_destroy_sq", 4 }
};

// ------------ Utility helpers ------------

static bool isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  return ExprHasName(OE, Name, C);
}

static bool isDestroyName(const CallEvent &Call, const char *Expected, CheckerContext &C) {
  if (!Expected)
    return false;
  return isCallNamed(Call, Expected, C);
}

static bool isOverScopedCleanupName(const CallEvent &Call, CheckerContext &C) {
  // Prefer Identifier if present, fallback to source-based contains check.
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    std::string L = ID->getName().lower();
    return (L.find("close") != std::string::npos) ||
           (L.find("free") != std::string::npos) ||
           (L.find("release") != std::string::npos);
  }
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  return ExprHasName(OE, "close", C) || ExprHasName(OE, "free", C) ||
         ExprHasName(OE, "release", C);
}

static bool isParamRegion(const MemRegion *R) {
  if (!R)
    return false;
  const MemRegion *Base = R->getBaseRegion();
  return Base && isa<ParamVarRegion>(Base);
}

// Extracts the resource base region from a creation call argument.
// Handles patterns like: &sq->sqn  -> returns region of 'sq' base
//                        sq        -> returns region of 'sq'
static const MemRegion *getResourceRegionFromCreateArg(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  // Address-of member, e.g., &sq->sqn
  if (const auto *UO = dyn_cast<UnaryOperator>(E->IgnoreParenCasts())) {
    if (UO->getOpcode() == UO_AddrOf) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
      if (const auto *ME = dyn_cast<MemberExpr>(Sub)) {
        const Expr *BaseE = ME->getBase();
        if (BaseE) {
          if (const MemRegion *R = getMemRegionFromExpr(BaseE, C)) {
            return R->getBaseRegion();
          }
        }
      }
      // &Var (fallback)
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (const MemRegion *R = getMemRegionFromExpr(DRE, C)) {
          return R->getBaseRegion();
        }
      }
    }
  }

  // Generic: sq (pointer/resource variable)
  if (const MemRegion *R = getMemRegionFromExpr(E, C)) {
    return R->getBaseRegion();
  }
  return nullptr;
}

// Heuristic: only warn inside functions that look like create/open helpers.
static bool isCreationLikeFunction(CheckerContext &C) {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return false;
  const Decl *D = LCtx->getDecl();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;
  std::string Name = FD->getNameAsString();
  for (char &ch : Name) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  return Name.find("create") != std::string::npos ||
         Name.find("open") != std::string::npos;
}

// ------------ Checker ------------

class SAGenTestChecker : public Checker<
                           check::PostCall,
                           check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
    : BT(new BugType(this, "Over-scoped cleanup in error path", "Resource Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void maybeRecordCreate(const CallEvent &Call, CheckerContext &C) const;
  void maybeReportOverScoped(const CallEvent &Call,
                             const MemRegion *ResReg,
                             const ResourceInfo &Info,
                             CheckerContext &C) const;
};

void SAGenTestChecker::maybeRecordCreate(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (const auto &Pair : KnownPairs) {
    if (!isCallNamed(Call, Pair.CreateName, C))
      continue;

    if (Pair.ResourceArgIndex >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Pair.ResourceArgIndex);
    if (!ArgE)
      continue;

    const MemRegion *ResReg = getResourceRegionFromCreateArg(ArgE, C);
    if (!ResReg)
      continue;

    bool ParamOwned = isParamRegion(ResReg);
    ResourceInfo Info(/*Step=*/1, /*ExpectedDestroy=*/Pair.DestroyName, /*IsParamOwned=*/ParamOwned);

    State = State->set<ResourceInfoMap>(ResReg, Info);
    C.addTransition(State);
    return; // only one match per call
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Record resource creation steps from known create functions.
  maybeRecordCreate(Call, C);
}

void SAGenTestChecker::maybeReportOverScoped(const CallEvent &Call,
                                             const MemRegion *ResReg,
                                             const ResourceInfo &Info,
                                             CheckerContext &C) const {
  if (!BT || !ResReg)
    return;

  // Heuristic narrowing: only warn in create/open-like functions.
  if (!isCreationLikeFunction(C))
    return;

  // Only warn if the resource belongs to a parameter (owned by the caller).
  if (!Info.IsParamOwned)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Over-scoped cleanup: call HW destroy instead of close/free to avoid double free", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // For each argument, see if it refers to a tracked resource.
  for (unsigned i = 0, e = Call.getNumArgs(); i != e; ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    const MemRegion *ArgReg = getMemRegionFromExpr(ArgE, C);
    if (!ArgReg)
      continue;
    ArgReg = ArgReg->getBaseRegion();

    // Look up resource info for this region.
    const ResourceInfo *Info = State->get<ResourceInfoMap>(ArgReg);
    if (!Info || Info->Step != 1)
      continue;

    // If this is the correct HW destroy, clear the state and accept it.
    if (isDestroyName(Call, Info->ExpectedDestroy, C)) {
      State = State->remove<ResourceInfoMap>(ArgReg);
      C.addTransition(State);
      continue;
    }

    // If this looks like an over-scoped cleanup (close/free/release), report.
    if (isOverScopedCleanupName(Call, C)) {
      maybeReportOverScoped(Call, ArgReg, *Info, C);
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects over-scoped cleanup in error paths (use HW destroy instead of close/free to avoid double free)",
      "");
}

} // namespace ento
} // namespace clang

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
