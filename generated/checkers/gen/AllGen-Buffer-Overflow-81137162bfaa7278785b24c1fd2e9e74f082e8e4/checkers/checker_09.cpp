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

// No custom program states needed for this checker.
namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unbounded string copy into fixed-size buffer",
                       "Buffer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helpers
  bool isStrcpy(const CallEvent &Call, CheckerContext &C) const;
  bool getFixedArraySizeFromExpr(const Expr *E, uint64_t &Size,
                                 CheckerContext &C) const;
  bool getConstStringLen(const Expr *E, uint64_t &Len) const;
  void reportUnbounded(const CallEvent &Call, const Expr *Dest,
                       CheckerContext &C) const;
  void reportPossibleOverflow(const CallEvent &Call, const Expr *Dest,
                              uint64_t DestCap, uint64_t SrcLen,
                              CheckerContext &C) const;
};

bool SAGenTestChecker::isStrcpy(const CallEvent &Call,
                                CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, "strcpy", C);
}

bool SAGenTestChecker::getConstStringLen(const Expr *E, uint64_t &Len) const {
  if (!E)
    return false;
  llvm::APInt StrSize;
  if (getStringSize(StrSize, E)) {
    Len = StrSize.getZExtValue();
    return true;
  }
  return false;
}

bool SAGenTestChecker::getFixedArraySizeFromExpr(const Expr *E,
                                                 uint64_t &Size,
                                                 CheckerContext &C) const {
  if (!E)
    return false;

  const Expr *EE = E->IgnoreParenImpCasts();

  // Case 1: DeclRefExpr to a constant array variable
  if (const auto *DRE = dyn_cast<DeclRefExpr>(EE)) {
    llvm::APInt ArrSz;
    if (getArraySizeFromExpr(ArrSz, DRE)) {
      Size = ArrSz.getZExtValue();
      return true;
    }
    // Fallback: inspect the variable type directly
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (const auto *CAT =
              C.getASTContext().getAsConstantArrayType(VD->getType())) {
        Size = CAT->getSize().getZExtValue();
        return true;
      }
    }
  }

  // Case 2: MemberExpr to a constant array field (e.g., di.name)
  if (const auto *ME = dyn_cast<MemberExpr>(EE)) {
    QualType QT = ME->getType();
    if (const auto *CAT = C.getASTContext().getAsConstantArrayType(QT)) {
      Size = CAT->getSize().getZExtValue();
      return true;
    }
    // Sometimes the member type may be retrieved from the FieldDecl
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      if (const auto *CAT =
              C.getASTContext().getAsConstantArrayType(FD->getType())) {
        Size = CAT->getSize().getZExtValue();
        return true;
      }
    }
  }

  // Case 3: ArraySubscriptExpr base
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(EE)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    return getFixedArraySizeFromExpr(Base, Size, C);
  }

  return false;
}

void SAGenTestChecker::reportUnbounded(const CallEvent &Call, const Expr *Dest,
                                       CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unbounded string copy into fixed-size buffer", N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  if (Dest)
    R->addRange(Dest->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportPossibleOverflow(const CallEvent &Call,
                                              const Expr *Dest, uint64_t DestCap,
                                              uint64_t SrcLen,
                                              CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Msg = Twine("strcpy may overflow fixed-size buffer (dest=")
                 .concat(Twine(DestCap))
                 .concat(", src_len=")
                 .concat(Twine(SrcLen))
                 .concat(")")
                 .str();

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  if (Dest)
    R->addRange(Dest->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isStrcpy(Call, C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *DestE = Call.getArgExpr(0);
  const Expr *SrcE = Call.getArgExpr(1);
  if (!DestE || !SrcE)
    return;

  uint64_t DestCap = 0;
  if (!getFixedArraySizeFromExpr(DestE, DestCap, C)) {
    // Only warn when destination is a known fixed-size array.
    return;
  }

  uint64_t SrcLen = 0;
  bool HasConstLen = getConstStringLen(SrcE, SrcLen);

  if (HasConstLen) {
    // Definite overflow if source length >= dest capacity (due to NUL).
    if (SrcLen >= DestCap) {
      reportPossibleOverflow(Call, DestE, DestCap, SrcLen, C);
    }
    // Else safe; do nothing.
  } else {
    // Unbounded copy into a fixed-size array; warn.
    reportUnbounded(Call, DestE, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects strcpy into fixed-size buffers; suggest bounded copy like strscpy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
