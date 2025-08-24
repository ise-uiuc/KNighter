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
#include "clang/AST/Attr.h"
#include "clang/Lex/Lexer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program-state: regions known to be zero-initialized (e.g., kzalloc/kcalloc)
REGISTER_SET_WITH_PROGRAMSTATE(ZeroInitObjs, const MemRegion*)
// Program-state: counter field regions that have been written at least once
REGISTER_SET_WITH_PROGRAMSTATE(InitializedCounterFieldRegions, const MemRegion*)

namespace {
class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Bind> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Flexible array misuse", "Memory Safety")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  bool isZeroInitAlloc(const CallEvent &Call, CheckerContext &C) const;
  bool isCopyFunction(const CallEvent &Call, unsigned &DestArgIndex, CheckerContext &C) const;

  const MemberExpr *getFlexArrayMemberExpr(const Expr *Dest, CheckerContext &C) const;
  bool isFlexibleArrayField(const FieldDecl *FD) const;

  bool fieldHasCountedBy(const FieldDecl *FD, CheckerContext &C) const;
  const FieldDecl *getCountedByCounterFD(const FieldDecl *FlexArrayFD, CheckerContext &C) const;
  bool isCounterFieldForAnyCountedBy(const FieldDecl *FD, CheckerContext &C) const;

  const MemRegion *getBaseObjectRegionFromMemberExpr(const MemberExpr *ME, CheckerContext &C) const;
  const MemRegion *getFieldRegionForCounter(const MemRegion *BaseObj, const FieldDecl *CounterFD, CheckerContext &C) const;

  void reportFlexibleArrayBeforeCounter(const Expr *DestE, CheckerContext &C) const;

  // Small text utilities
  bool getDeclSourceText(StringRef &Out, const Decl *D, CheckerContext &C) const;
  static StringRef trimParensAndSpaces(StringRef S);
};

bool SAGenTestChecker::isZeroInitAlloc(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // Known zero-initializing allocators
  static const char *Names[] = {
      "kzalloc", "kcalloc", "kvzalloc",
      "devm_kzalloc", "devm_kcalloc",
      "kzalloc_node", "kcalloc_node"
  };

  for (const char *N : Names) {
    if (ExprHasName(OriginExpr, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isCopyFunction(const CallEvent &Call, unsigned &DestArgIndex, CheckerContext &C) const {
  DestArgIndex = 0;
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  static const char *Names[] = {
      "memcpy", "__memcpy", "__builtin_memcpy",
      "memmove", "__memmove", "__builtin_memmove"
  };

  for (const char *N : Names) {
    if (ExprHasName(OriginExpr, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isFlexibleArrayField(const FieldDecl *FD) const {
  if (!FD)
    return false;

  // Use the available API in Clang 18.
  if (FD->isFlexibleArrayMemberLike())
    return true;

  QualType QT = FD->getType();
  if (QT.isNull())
    return false;

  const Type *Ty = QT.getTypePtrOrNull();
  if (!Ty)
    return false;

  if (isa<IncompleteArrayType>(Ty))
    return true;

  return false;
}

const MemberExpr *SAGenTestChecker::getFlexArrayMemberExpr(const Expr *Dest, CheckerContext &C) const {
  if (!Dest)
    return nullptr;

  // Try to find a MemberExpr in the destination expression tree
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Dest);
  if (!ME)
    return nullptr;

  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FD = dyn_cast_or_null<FieldDecl>(VD);
  if (!FD)
    return nullptr;

  if (!isFlexibleArrayField(FD))
    return nullptr;

  // Must have counted_by annotation as well
  if (!fieldHasCountedBy(FD, C))
    return nullptr;

  return ME;
}

bool SAGenTestChecker::fieldHasCountedBy(const FieldDecl *FD, CheckerContext &C) const {
  if (!FD)
    return false;

  // Prefer the real attribute when available
  if (FD->hasAttr<CountedByAttr>())
    return true;

  // Fallback: look for "__counted_by(" or "counted_by(" spelling in the declaration source
  StringRef Text;
  if (getDeclSourceText(Text, FD, C)) {
    if (Text.contains("__counted_by(") || Text.contains("counted_by("))
      return true;
  }
  return false;
}

const FieldDecl *SAGenTestChecker::getCountedByCounterFD(const FieldDecl *FlexArrayFD, CheckerContext &C) const {
  if (!FlexArrayFD)
    return nullptr;

  // If Clang provides the attribute, try to get the counter directly
  if (auto *A = FlexArrayFD->getAttr<CountedByAttr>()) {
    // Newer Clang versions expose the referenced field; try known accessors if available.
    // Use a conservative approach if API details differ: try to retrieve the field by name from attr spelling.
    // Fall through to text parsing if we cannot retrieve it directly.
    (void)A;
  }

  // Fallback path: parse the attribute argument to get the counter's field name
  StringRef Text;
  if (!getDeclSourceText(Text, FlexArrayFD, C))
    return nullptr;

  size_t Pos = Text.find("counted_by");
  if (Pos == StringRef::npos)
    Pos = Text.find("__counted_by");
  if (Pos == StringRef::npos)
    return nullptr;

  size_t L = Text.find('(', Pos);
  size_t R = (L == StringRef::npos) ? StringRef::npos : Text.find(')', L + 1);
  if (L == StringRef::npos || R == StringRef::npos || R <= L + 1)
    return nullptr;

  StringRef Param = Text.slice(L + 1, R);
  Param = trimParensAndSpaces(Param);
  if (Param.empty())
    return nullptr;

  const RecordDecl *RD = dyn_cast<RecordDecl>(FlexArrayFD->getParent());
  if (!RD)
    return nullptr;

  for (const FieldDecl *F : RD->fields()) {
    if (F->getName() == Param)
      return F;
  }
  return nullptr;
}

bool SAGenTestChecker::isCounterFieldForAnyCountedBy(const FieldDecl *FD, CheckerContext &C) const {
  if (!FD)
    return false;

  const RecordDecl *RD = dyn_cast<RecordDecl>(FD->getParent());
  if (!RD)
    return false;

  for (const FieldDecl *F : RD->fields()) {
    if (!isFlexibleArrayField(F))
      continue;
    if (!fieldHasCountedBy(F, C))
      continue;

    const FieldDecl *Counter = getCountedByCounterFD(F, C);
    if (Counter == FD)
      return true;
  }
  return false;
}

const MemRegion *SAGenTestChecker::getBaseObjectRegionFromMemberExpr(const MemberExpr *ME, CheckerContext &C) const {
  if (!ME)
    return nullptr;
  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return nullptr;

  const MemRegion *Reg = getMemRegionFromExpr(BaseE, C);
  if (!Reg)
    return nullptr;

  Reg = Reg->getBaseRegion();
  return Reg;
}

const MemRegion *SAGenTestChecker::getFieldRegionForCounter(const MemRegion *BaseObj, const FieldDecl *CounterFD, CheckerContext &C) const {
  if (!BaseObj || !CounterFD)
    return nullptr;
  const SubRegion *BaseSR = dyn_cast<SubRegion>(BaseObj);
  if (!BaseSR)
    return nullptr;
  const FieldRegion *FR = BaseObj->getMemRegionManager().getFieldRegion(CounterFD, BaseSR);
  return FR;
}

bool SAGenTestChecker::getDeclSourceText(StringRef &Out, const Decl *D, CheckerContext &C) const {
  if (!D)
    return false;
  SourceRange SR = D->getSourceRange();
  if (SR.isInvalid())
    return false;

  CharSourceRange CR = CharSourceRange::getTokenRange(SR);
  Out = Lexer::getSourceText(CR, C.getSourceManager(), C.getLangOpts());
  return !Out.empty();
}

StringRef SAGenTestChecker::trimParensAndSpaces(StringRef S) {
  S = S.trim();
  while (!S.empty() && (S.front() == '(' || S.front() == ' ' || S.front() == '\t'))
    S = S.drop_front();
  while (!S.empty() && (S.back() == ')' || S.back() == ' ' || S.back() == '\t'))
    S = S.drop_back();
  return S.trim();
}

void SAGenTestChecker::reportFlexibleArrayBeforeCounter(const Expr *DestE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Flexible array accessed before setting its __counted_by counter", N);
  if (DestE)
    R->addRange(DestE->getSourceRange());
  C.emitReport(std::move(R));
}

// Callbacks

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroInitAlloc(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  const MemRegion *R = Ret.getAsRegion();
  if (!R)
    return;
  R = R->getBaseRegion();
  if (!R)
    return;

  State = State->add<ZeroInitObjs>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned DestIdx = 0;
  if (!isCopyFunction(Call, DestIdx, C))
    return;

  if (DestIdx >= Call.getNumArgs())
    return;

  const Expr *DestE = Call.getArgExpr(DestIdx);
  if (!DestE)
    return;

  const MemberExpr *ME = getFlexArrayMemberExpr(DestE, C);
  if (!ME)
    return;

  const FieldDecl *FlexFD = dyn_cast_or_null<FieldDecl>(ME->getMemberDecl());
  if (!FlexFD)
    return;

  const FieldDecl *CounterFD = getCountedByCounterFD(FlexFD, C);
  if (!CounterFD)
    return;

  const MemRegion *BaseObj = getBaseObjectRegionFromMemberExpr(ME, C);
  if (!BaseObj)
    return;

  ProgramStateRef State = C.getState();

  // Only warn for known zero-initialized objects (e.g., kzalloc)
  if (!State->contains<ZeroInitObjs>(BaseObj))
    return;

  const MemRegion *CounterFR = getFieldRegionForCounter(BaseObj, CounterFD, C);
  if (!CounterFR)
    return;

  // If counter was already initialized, no bug.
  if (State->contains<InitializedCounterFieldRegions>(CounterFR))
    return;

  // Report: accessing flexible array before setting its counted_by counter.
  reportFlexibleArrayBeforeCounter(DestE, C);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  R = R->getBaseRegion();
  if (!R)
    return;

  const FieldRegion *FR = dyn_cast<FieldRegion>(R);
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD)
    return;

  // Only track writes to fields that are counters for __counted_by flex arrays.
  if (!isCounterFieldForAnyCountedBy(FD, C))
    return;

  ProgramStateRef State = C.getState();
  State = State->add<InitializedCounterFieldRegions>(FR);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memcpy/memmove into __counted_by flexible-array before its counter is set",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
