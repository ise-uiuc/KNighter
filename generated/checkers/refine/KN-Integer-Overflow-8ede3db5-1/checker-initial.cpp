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

// No custom program state is required.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Lossy cast hides overflow in add_overflow check", "API Misuse")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      static bool isAddOverflowLike(const CallEvent &Call, CheckerContext &C);
      static const Expr *getExplicitNarrowingCastOfSizeRelated(const Expr *E, ASTContext &ACtx);
};

static bool isSignedIntegerType(QualType QT) {
  if (QT.isNull()) return false;
  const Type *Ty = QT.getTypePtrOrNull();
  if (!Ty) return false;
  return QT->isIntegerType() && QT->isSignedIntegerType();
}

bool SAGenTestChecker::isAddOverflowLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (Origin) {
    // Prefer direct source-text name matching on the origin expression.
    if (ExprHasName(Origin, "check_add_overflow", C))
      return true;
    if (ExprHasName(Origin, "__builtin_add_overflow", C))
      return true;
    // Some kernels use macros/wrappers that still contain "add_overflow".
    if (ExprHasName(Origin, "add_overflow", C))
      return true;
  }

  // Fallback: use callee identifier if available.
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef N = ID->getName();
    if (N == "check_add_overflow")
      return true;
    if (N.contains("add_overflow"))
      return true;
  }
  return false;
}

// Return the explicit cast expression if E is a top-level explicit cast that
// converts a size-related value (sizeof or size_t) to a signed integer type
// that is narrower, or same-width signed from unsigned. Otherwise, return null.
const Expr *SAGenTestChecker::getExplicitNarrowingCastOfSizeRelated(const Expr *E,
                                                                    ASTContext &ACtx) {
  if (!E)
    return nullptr;
  const Expr *Top = E->IgnoreParens(); // do not ignore explicit casts

  // In C, explicit casts are CStyleCastExpr.
  const auto *CSE = dyn_cast<CStyleCastExpr>(Top);
  if (!CSE)
    return nullptr;

  QualType ToT = CSE->getType().getCanonicalType();
  if (!isSignedIntegerType(ToT))
    return nullptr;

  const Expr *Sub = CSE->getSubExpr();
  if (!Sub)
    return nullptr;

  // Ignore parens around the subexpr; keep implicit casts if any to read FromT.
  const Expr *CoreSub = Sub->IgnoreParens();
  QualType FromT = CoreSub->getType().getCanonicalType();
  if (FromT.isNull())
    return nullptr;

  // Determine if the subexpr is size-related: either sizeof(...) expr,
  // or the type of the subexpr is size_t.
  bool IsSizeof = false;
  if (const auto *UETT = dyn_cast<UnaryExprOrTypeTraitExpr>(CoreSub)) {
    if (UETT->getKind() == UETT_SizeOf)
      IsSizeof = true;
  }

  bool IsSizeT = (FromT == ACtx.getSizeType());
  if (!IsSizeof && !IsSizeT)
    return nullptr;

  // Signedness and bit widths.
  bool FromIsUnsigned = FromT->isUnsignedIntegerType();
  unsigned FromBits = ACtx.getTypeSize(FromT);
  unsigned ToBits   = ACtx.getTypeSize(ToT);

  // Problematic if:
  // - To is signed and narrower than From (truncation).
  // - Or same width, converting from unsigned to signed (can flip negative).
  if (ToBits < FromBits)
    return CSE;
  if (ToBits == FromBits && FromIsUnsigned)
    return CSE;

  return nullptr;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isAddOverflowLike(Call, C))
    return;

  if (Call.getNumArgs() != 3)
    return;

  ASTContext &ACtx = C.getASTContext();

  const Expr *Arg0 = Call.getArgExpr(0);
  const Expr *Arg1 = Call.getArgExpr(1);

  const Expr *BadA = getExplicitNarrowingCastOfSizeRelated(Arg0, ACtx);
  const Expr *BadB = getExplicitNarrowingCastOfSizeRelated(Arg1, ACtx);

  if (!BadA && !BadB)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Lossy cast to int in check_add_overflow may hide overflow; avoid casting sizeof/size_t to int", N);

  if (BadA)
    R->addRange(BadA->getSourceRange());
  if (BadB)
    R->addRange(BadB->getSourceRange());

  if (const Expr *OE = Call.getOriginExpr())
    R->addRange(OE->getSourceRange());

  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects lossy casts of size-related operands in add_overflow checks that can hide overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
