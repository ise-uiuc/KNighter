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
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the environment (see prompt).
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};
bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

// Track for each MemRegion (typically a local variable) whether it currently
// stores a value that came from sizeof-only, or a multiplication with sizeof.
namespace clang {
namespace ento {
REGISTER_MAP_WITH_PROGRAMSTATE(SizeOriginMap, const MemRegion *, unsigned)
} // namespace ento
} // namespace clang

namespace {

enum SizeOrigin : unsigned {
  ORIG_None = 0,
  ORIG_SizeofOnly = 1,     // E.g. sizeof(T) or sizeof(*p)
  ORIG_MulWithSizeof = 2   // E.g. count * sizeof(T), exactly one side size-like
};

class SAGenTestChecker
    : public Checker<check::PreCall, check::PostStmt<DeclStmt>,
                     check::PostStmt<BinaryOperator>, check::RegionChanges> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use memdup_array_user for array copy",
                       "API Misuse")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;
  ProgramStateRef
  checkRegionChanges(ProgramStateRef State, const InvalidatedSymbols *Invalidated,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
                     const CallEvent *Call) const;

private:
  static bool isMemdupUser(const CallEvent &Call);

  static bool isSizeofExpr(const Expr *E);

  // Return true if E is exactly a multiply where exactly one side is size-like:
  // - Direct sizeof(...)
  // - OR the side is a DeclRef/region previously tracked as ORIG_SizeofOnly
  // If so, returns that BO via OutMul, and sets WhichSizeSideIsLeft accordingly.
  static bool isTopLevelMulWithExactlyOneSizeLike(const Expr *E,
                                                  CheckerContext &C,
                                                  const BinaryOperator *&OutMul,
                                                  bool &SizeSideIsLeft);

  // True if E is a plain sizeof(...) (after ignoring casts/parens).
  static bool isPlainSizeofOnly(const Expr *E) { return isSizeofExpr(E); }

  // Consult state: get origin for a region.
  static unsigned getOriginForRegion(ProgramStateRef State, const MemRegion *MR) {
    if (!MR) return ORIG_None;
    const unsigned *P = State->get<SizeOriginMap>(MR);
    return P ? *P : ORIG_None;
  }

  // Determine "origin" for an expression using both syntax and tracked state.
  static unsigned classifyExprOrigin(const Expr *E, CheckerContext &C);

  // Set origin for a region in state.
  static ProgramStateRef setRegionOrigin(ProgramStateRef State, const MemRegion *MR,
                                         unsigned Origin) {
    if (!MR) return State;
    if (Origin == ORIG_None)
      return State->remove<SizeOriginMap>(MR);
    return State->set<SizeOriginMap>(MR, Origin);
  }

  // Helper: whether an expression is "size-like" (direct sizeof or a variable
  // known to be sizeof-only).
  static bool isSizeLikeExpr(const Expr *E, CheckerContext &C) {
    if (!E) return false;
    if (isSizeofExpr(E))
      return true;
    if (const MemRegion *MR = getMemRegionFromExpr(E->IgnoreParenImpCasts(), C)) {
      return getOriginForRegion(C.getState(), MR) == ORIG_SizeofOnly;
    }
    return false;
  }
};

bool SAGenTestChecker::isMemdupUser(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == "memdup_user";
  return false;
}

bool SAGenTestChecker::isSizeofExpr(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E))
    return U->getKind() == UETT_SizeOf;
  return false;
}

bool SAGenTestChecker::isTopLevelMulWithExactlyOneSizeLike(
    const Expr *E, CheckerContext &C, const BinaryOperator *&OutMul,
    bool &SizeSideIsLeft) {
  OutMul = nullptr;
  SizeSideIsLeft = false;
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return false;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
  bool LIsSizeLike = isSizeLikeExpr(L, C);
  bool RIsSizeLike = isSizeLikeExpr(R, C);

  // Exactly one side size-like (count * sizeof(elem)).
  if (LIsSizeLike == RIsSizeLike)
    return false;

  OutMul = BO;
  SizeSideIsLeft = LIsSizeLike;
  return true;
}

unsigned SAGenTestChecker::classifyExprOrigin(const Expr *E, CheckerContext &C) {
  if (!E) return ORIG_None;

  // 1) Direct sizeof-only?
  if (isPlainSizeofOnly(E))
    return ORIG_SizeofOnly;

  // 2) Direct mul with exactly one size-like side?
  const BinaryOperator *TopMul = nullptr;
  bool SizeSideIsLeft = false;
  if (isTopLevelMulWithExactlyOneSizeLike(E, C, TopMul, SizeSideIsLeft))
    return ORIG_MulWithSizeof;

  // 3) Reference to a tracked region?
  if (const MemRegion *MR = getMemRegionFromExpr(E->IgnoreParenImpCasts(), C)) {
    return getOriginForRegion(C.getState(), MR);
  }

  return ORIG_None;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isMemdupUser(Call))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *SizeArg = Call.getArgExpr(1);
  if (!SizeArg)
    return;

  // Suppress when it's a plain sizeof(...) (dup of a single struct/object).
  if (isPlainSizeofOnly(SizeArg))
    return;

  // Warn when the argument is a "count * sizeof(elem)" at the call site.
  const BinaryOperator *TopMul = nullptr;
  bool SizeSideIsLeft = false;
  if (isTopLevelMulWithExactlyOneSizeLike(SizeArg, C, TopMul, SizeSideIsLeft)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, "
        "count * elem_size); multiplication may overflow.",
        N);
    R->addRange(TopMul->getSourceRange());
    C.emitReport(std::move(R));
    return;
  }

  // If not directly a multiply at the call site, check if the argument
  // refers to a tracked variable with origin MulWithSizeof.
  unsigned Origin = classifyExprOrigin(SizeArg, C);
  if (Origin == ORIG_MulWithSizeof) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, "
        "count * elem_size); multiplication may overflow.",
        N);
    R->addRange(SizeArg->getSourceRange());
    C.emitReport(std::move(R));
    return;
  }

  // Otherwise, not our pattern.
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  // Track initializers like: size_t sz = count * sizeof(T); or sz = sizeof(T);
  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD || !VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    if (!Init)
      continue;

    unsigned Origin = classifyExprOrigin(Init, C);
    // We only care about originating from sizeof-only or mul-with-sizeof.
    if (Origin == ORIG_None)
      continue;

    ProgramStateRef State = C.getState();
    const VarRegion *VR =
        C.getSValBuilder().getRegionManager().getVarRegion(VD, C.getLocationContext());
    if (!VR)
      continue;

    State = setRegionOrigin(State, VR, Origin);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPostStmt(const BinaryOperator *BO,
                                     CheckerContext &C) const {
  // Track assignments like: sz = count * sizeof(T); or sz = sizeof(T);
  if (!BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  const MemRegion *MR = getMemRegionFromExpr(LHS, C);
  if (!MR)
    return;

  unsigned Origin = classifyExprOrigin(RHS, C);

  ProgramStateRef State = C.getState();
  // Update region origin. If no interesting origin, clear it to avoid stale info.
  State = setRegionOrigin(State, MR, Origin);
  C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Invalidated,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
    const CallEvent *Call) const {
  // Drop any tracked origins for invalidated regions.
  for (const MemRegion *MR : Regions) {
    State = State->remove<SizeOriginMap>(MR);
  }
  for (const MemRegion *MR : ExplicitRegions) {
    State = State->remove<SizeOriginMap>(MR);
  }
  return State;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memdup_user used with count * sizeof(...) and suggests "
      "memdup_array_user",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
