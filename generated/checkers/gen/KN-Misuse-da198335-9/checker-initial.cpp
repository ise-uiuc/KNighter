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
#include "clang/AST/Attr.h"
#include "clang/Lex/Lexer.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map: track whether a specific count field (as a FieldRegion) is initialized.
// Key: const MemRegion* (the FieldRegion for the count field)
// Val: char (1 means initialized)
REGISTER_MAP_WITH_PROGRAMSTATE(CountInitMap, const MemRegion*, char)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Write before count init", "API Misuse")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isFlexibleArray(const FieldDecl *FD);
      static bool isMemWriteLikeCall(const CallEvent &Call, CheckerContext &C);
      static bool sizeArgDefinitelyZero(const CallEvent &Call, CheckerContext &C);
      static const MemberExpr *findMemberExprInArgToFAM(const Expr *Arg,
                                                        const FieldDecl *&FAMFieldOut,
                                                        const FieldDecl *&CountFieldOut,
                                                        CheckerContext &C);
      static const MemRegion* getBaseRegionOfME(const MemberExpr *ME, CheckerContext &C);

      static const FieldDecl* getCountFieldFromCountedBy(const FieldDecl *FAMField,
                                                         CheckerContext &C);
      static bool fieldIsCountFieldInRecord(const FieldDecl *FD, CheckerContext &C);

      void reportWriteBeforeCountInit(StringRef Msg, const Stmt *S, CheckerContext &C) const;
};

// ------------------------ Helper implementations ------------------------

bool SAGenTestChecker::isFlexibleArray(const FieldDecl *FD) {
  if (!FD) return false;
  QualType QT = FD->getType();
  if (const auto *IAT = dyn_cast<IncompleteArrayType>(QT.getTypePtr()))
    (void)IAT; // just to silence unused warning in some builds
  if (QT->isIncompleteArrayType())
    return true;
  if (const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
    return CAT->getSize() == 0;
  }
  return false;
}

const FieldDecl* SAGenTestChecker::getCountFieldFromCountedBy(const FieldDecl *FAMField,
                                                              CheckerContext &C) {
  if (!FAMField) return nullptr;

  // Check the attribute presence.
  if (!FAMField->hasAttrs())
    return nullptr;

  const CountedByAttr *A = FAMField->getAttr<CountedByAttr>();
  if (!A)
    return nullptr;

  // Extract the spelled attribute text and parse the argument name.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &Lang = C.getLangOpts();

  // The attribute's source range should contain something like "__counted_by(name)" or "counted_by(name)".
  SourceRange R = A->getRange();
  if (R.isInvalid())
    return nullptr;

  CharSourceRange CR = CharSourceRange::getTokenRange(R);
  StringRef AttrText = Lexer::getSourceText(CR, SM, Lang);
  if (AttrText.empty())
    return nullptr;

  // Find parameter inside parentheses.
  size_t lpos = AttrText.find('(');
  size_t rpos = AttrText.rfind(')');
  if (lpos == StringRef::npos || rpos == StringRef::npos || rpos <= lpos + 1)
    return nullptr;

  StringRef Param = AttrText.slice(lpos + 1, rpos).trim();
  if (Param.empty())
    return nullptr;

  // Sometimes the macro could expand weirdly; keep it simple: expect identifier.
  // Strip potential casts or address-of (just in case), though kernel uses a bare identifier.
  while (!Param.empty() && (Param.front() == '&' || Param.front() == '*'))
    Param = Param.drop_front().ltrim();

  // Lookup a field with matching name in the same record.
  const RecordDecl *RD = FAMField->getParent();
  if (!RD)
    return nullptr;

  for (const FieldDecl *FD : RD->fields()) {
    if (FD && FD->getIdentifier() && FD->getName() == Param)
      return FD;
  }

  return nullptr;
}

bool SAGenTestChecker::fieldIsCountFieldInRecord(const FieldDecl *FD, CheckerContext &C) {
  if (!FD) return false;
  const RecordDecl *RD = FD->getParent();
  if (!RD) return false;

  for (const FieldDecl *G : RD->fields()) {
    if (!G) continue;
    if (!isFlexibleArray(G))
      continue;
    const FieldDecl *CF = getCountFieldFromCountedBy(G, C);
    if (CF == FD)
      return true;
  }
  return false;
}

bool SAGenTestChecker::isMemWriteLikeCall(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  return ExprHasName(OE, "memcpy", C) || ExprHasName(OE, "memmove", C);
}

bool SAGenTestChecker::sizeArgDefinitelyZero(const CallEvent &Call, CheckerContext &C) {
  if (Call.getNumArgs() < 3)
    return false;

  const Expr *SizeE = Call.getArgExpr(2);
  if (!SizeE)
    return false;

  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, SizeE, C)) {
    return Res == 0;
  }
  return false;
}

const MemberExpr *SAGenTestChecker::findMemberExprInArgToFAM(const Expr *Arg,
                                                             const FieldDecl *&FAMFieldOut,
                                                             const FieldDecl *&CountFieldOut,
                                                             CheckerContext &C) {
  FAMFieldOut = nullptr;
  CountFieldOut = nullptr;

  if (!Arg)
    return nullptr;

  // Search downwards for a MemberExpr
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Arg);
  if (!ME)
    return nullptr;

  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FD = dyn_cast_or_null<FieldDecl>(VD);
  if (!FD)
    return nullptr;

  if (!isFlexibleArray(FD))
    return nullptr;

  const FieldDecl *CountFD = getCountFieldFromCountedBy(FD, C);
  if (!CountFD)
    return nullptr;

  FAMFieldOut = FD;
  CountFieldOut = CountFD;
  return ME;
}

const MemRegion* SAGenTestChecker::getBaseRegionOfME(const MemberExpr *ME, CheckerContext &C) {
  if (!ME)
    return nullptr;
  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

void SAGenTestChecker::reportWriteBeforeCountInit(StringRef Msg, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// ------------------------ Checker callbacks ------------------------

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isMemWriteLikeCall(Call, C))
    return;

  // Destination pointer is arg0.
  if (Call.getNumArgs() < 1)
    return;
  const Expr *DstE = Call.getArgExpr(0);
  if (!DstE)
    return;

  const FieldDecl *FAMField = nullptr;
  const FieldDecl *CountField = nullptr;
  const MemberExpr *DstME = findMemberExprInArgToFAM(DstE, FAMField, CountField, C);
  if (!DstME || !FAMField || !CountField)
    return;

  // Get the base object region (e.g., tz)
  const MemRegion *Base = getBaseRegionOfME(DstME, C);
  if (!Base)
    return;

  // Compute the FieldRegion for the count field on this base.
  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  const SubRegion *Super = dyn_cast<SubRegion>(Base);
  if (!Super)
    return;

  const FieldRegion *CountFR = MRMgr.getFieldRegion(CountField, Super);
  if (!CountFR)
    return;

  ProgramStateRef State = C.getState();
  const char *Inited = State->get<CountInitMap>(CountFR);
  if (Inited) {
    // Already initialized on this path.
    return;
  }

  // Optional: if size is definitely zero, skip warning
  if (sizeArgDefinitelyZero(Call, C))
    return;

  // Report: write to counted_by FAM before initializing count field.
  reportWriteBeforeCountInit("Write to __counted_by() flexible array before initializing its count field",
                             Call.getOriginExpr(), C);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *Reg = Loc.getAsRegion();
  if (!Reg)
    return;

  ProgramStateRef State = C.getState();
  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();

  // Case 1: Assigning to a field: if it's the count field, mark initialized.
  if (const auto *FR = dyn_cast<FieldRegion>(Reg)) {
    const FieldDecl *FD = FR->getDecl();
    if (FD && fieldIsCountFieldInRecord(FD, C)) {
      // Mark this specific count field region as initialized.
      State = State->set<CountInitMap>(FR, 1);
      C.addTransition(State);
      return;
    }
  }

  // Case 2: Direct write into the flexible array via element region: tz->arr[i] = ...
  if (const auto *ER = dyn_cast<ElementRegion>(Reg)) {
    const MemRegion *SR = ER->getSuperRegion();
    const auto *FReg = dyn_cast<FieldRegion>(SR);
    if (!FReg)
      return;

    const FieldDecl *FAMField = FReg->getDecl();
    if (!FAMField || !isFlexibleArray(FAMField))
      return;

    const FieldDecl *CountField = getCountFieldFromCountedBy(FAMField, C);
    if (!CountField)
      return;

    // Super region of the field is the base object region (tz).
    const SubRegion *Super = dyn_cast<SubRegion>(FReg->getSuperRegion());
    if (!Super)
      return;

    const FieldRegion *CountFR = MRMgr.getFieldRegion(CountField, Super);
    if (!CountFR)
      return;

    const char *Inited = State->get<CountInitMap>(CountFR);
    if (!Inited) {
      // Count field not yet initialized; report.
      reportWriteBeforeCountInit("Write to __counted_by() flexible array before initializing its count field", S, C);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect writes to __counted_by() flexible arrays before initializing the count field",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
