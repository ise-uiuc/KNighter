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
#include "clang/AST/Attr.h"
#include "clang/AST/Type.h"
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: whether the struct object (owner) is zero-initialized.
REGISTER_MAP_WITH_PROGRAMSTATE(OwnerZeroedMap, const MemRegion*, bool)
// Program state: whether the __counted_by length field has been initialized.
REGISTER_MAP_WITH_PROGRAMSTATE(OwnerCountSetMap, const MemRegion*, bool)
// Program state: cache the FieldDecl* of the length field for an owner.
REGISTER_MAP_WITH_PROGRAMSTATE(OwnerCountFieldMap, const MemRegion*, const FieldDecl*)

namespace {
class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Flexible-array access before __counted_by init",
                       "Memory Safety")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helpers
  static bool calleeIs(const CallEvent &Call, StringRef Name, CheckerContext &C);

  static bool isZeroAllocFunction(const CallEvent &Call, CheckerContext &C);
  static bool isMemsetZero(const CallEvent &Call, CheckerContext &C);
  static bool isMemcpyLike(const CallEvent &Call, CheckerContext &C);

  static const MemberExpr* getAsMember(const Expr *E);
  static bool isFlexibleArrayCountedBy(const FieldDecl *FlexFD, const FieldDecl *&CountFD);
  static bool getFlexArrayAndOwner(const Expr *E,
                                   const MemberExpr *&FlexME,
                                   const FieldDecl *&FlexFD,
                                   const FieldDecl *&CountFD,
                                   const Expr *&OwnerBaseExpr);

  static const FieldDecl* findCountFieldFromOwnerRecord(const RecordDecl *RD);

  static ProgramStateRef ensureOwnerCountFieldMapping(ProgramStateRef State,
                                                      const MemRegion *OwnerReg,
                                                      const FieldDecl *CountFD);
};

// Check if the call's callee matches the provided name.
// Prefer using Call.getCalleeIdentifier(); fallback to source-text match.
bool SAGenTestChecker::calleeIs(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    if (ID->getName() == Name) return true;
  }
  if (const Expr *OE = Call.getOriginExpr()) {
    if (ExprHasName(OE, Name, C)) return true;
  }
  return false;
}

bool SAGenTestChecker::isZeroAllocFunction(const CallEvent &Call, CheckerContext &C) {
  // Known zero-initializing allocators in the kernel
  static const char *Names[] = {
      "kzalloc", "kcalloc", "kvzalloc",
      "devm_kzalloc", "devm_kcalloc",
      "kzalloc_node", "kcalloc_node"
  };
  for (auto *N : Names) {
    if (calleeIs(Call, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isMemsetZero(const CallEvent &Call, CheckerContext &C) {
  if (!(calleeIs(Call, "memset", C) || calleeIs(Call, "__memset", C)))
    return false;

  if (Call.getNumArgs() < 2)
    return false;

  const Expr *ValExpr = Call.getArgExpr(1);
  if (!ValExpr)
    return false;

  llvm::APSInt Res;
  if (!EvaluateExprToInt(Res, ValExpr, C))
    return false;

  return Res.isZero();
}

bool SAGenTestChecker::isMemcpyLike(const CallEvent &Call, CheckerContext &C) {
  return calleeIs(Call, "memcpy", C) ||
         calleeIs(Call, "__memcpy", C) ||
         calleeIs(Call, "memmove", C);
}

const MemberExpr* SAGenTestChecker::getAsMember(const Expr *E) {
  if (!E) return nullptr;
  const Expr *Cur = E->IgnoreParenImpCasts();
  if (const auto *ME = dyn_cast<MemberExpr>(Cur))
    return ME;

  if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
    if (UO->getOpcode() == UO_AddrOf || UO->getOpcode() == UO_Deref) {
      const Expr *SE = UO->getSubExpr();
      if (!SE) return nullptr;
      return dyn_cast<MemberExpr>(SE->IgnoreParenImpCasts());
    }
  }

  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Cur)) {
    const Expr *Base = ASE->getBase();
    if (!Base) return nullptr;
    return dyn_cast<MemberExpr>(Base->IgnoreParenImpCasts());
  }

  return nullptr;
}

bool SAGenTestChecker::isFlexibleArrayCountedBy(const FieldDecl *FlexFD,
                                                const FieldDecl *&CountFD) {
  CountFD = nullptr;
  if (!FlexFD)
    return false;

  // Must be a flexible array member (or similar).
  bool IsFlex = FlexFD->isFlexibleArrayMember() ||
                FlexFD->getType()->isIncompleteArrayType();
  if (!IsFlex)
    return false;

  if (const auto *CBA = FlexFD->getAttr<CountedByAttr>()) {
#if CLANG_VERSION_MAJOR >= 18
    if (const IdentifierInfo *II = CBA->getCountedByField()) {
      const RecordDecl *RD = FlexFD->getParent();
      if (!RD)
        return false;
      for (const FieldDecl *FD : RD->fields()) {
        if (FD->getIdentifier() == II) {
          CountFD = FD;
          return true;
        }
      }
    }
#else
    return false;
#endif
  }
  return false;
}

bool SAGenTestChecker::getFlexArrayAndOwner(const Expr *E,
                                            const MemberExpr *&FlexME,
                                            const FieldDecl *&FlexFD,
                                            const FieldDecl *&CountFD,
                                            const Expr *&OwnerBaseExpr) {
  FlexME = nullptr;
  FlexFD = nullptr;
  CountFD = nullptr;
  OwnerBaseExpr = nullptr;

  const MemberExpr *ME = getAsMember(E);
  if (!ME)
    return false;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return false;

  const FieldDecl *CFD = nullptr;
  if (!isFlexibleArrayCountedBy(FD, CFD))
    return false;

  FlexME = ME;
  FlexFD = FD;
  CountFD = CFD;
  OwnerBaseExpr = ME->getBase();
  return true;
}

const FieldDecl* SAGenTestChecker::findCountFieldFromOwnerRecord(const RecordDecl *RD) {
  if (!RD)
    return nullptr;

  for (const FieldDecl *FD : RD->fields()) {
    const FieldDecl *CountFD = nullptr;
    if (isFlexibleArrayCountedBy(FD, CountFD) && CountFD)
      return CountFD;
  }
  return nullptr;
}

ProgramStateRef SAGenTestChecker::ensureOwnerCountFieldMapping(ProgramStateRef State,
                                                               const MemRegion *OwnerReg,
                                                               const FieldDecl *CountFD) {
  if (!State || !OwnerReg)
    return State;

  const FieldDecl *Mapped = nullptr;
  if (const auto *P = State->get<OwnerCountFieldMap>(OwnerReg))
    Mapped = *P;
  if (!Mapped && CountFD) {
    State = State->set<OwnerCountFieldMap>(OwnerReg, CountFD);
  }

  // Initialize the "count set" flag to false if absent.
  if (!State->get<OwnerCountSetMap>(OwnerReg)) {
    State = State->set<OwnerCountSetMap>(OwnerReg, false);
  }

  return State;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Zero-initializing allocators: mark the returned region as zeroed.
  if (isZeroAllocFunction(Call, C)) {
    const MemRegion *MR = Call.getReturnValue().getAsRegion();
    if (MR) {
      MR = MR->getBaseRegion();
      State = State->set<OwnerZeroedMap>(MR, true);
      // Initialize count-set flag to false if absent.
      if (!State->get<OwnerCountSetMap>(MR)) {
        State = State->set<OwnerCountSetMap>(MR, false);
      }
      C.addTransition(State);
    }
    return;
  }

  // memset(..., 0, ...): mark destination as zeroed.
  if (isMemsetZero(Call, C) && Call.getNumArgs() > 0) {
    const Expr *DestE = Call.getArgExpr(0);
    if (DestE) {
      const MemRegion *MR = getMemRegionFromExpr(DestE, C);
      if (MR) {
        MR = MR->getBaseRegion();
        State = State->set<OwnerZeroedMap>(MR, true);
        if (!State->get<OwnerCountSetMap>(MR)) {
          State = State->set<OwnerCountSetMap>(MR, false);
        }
        C.addTransition(State);
      }
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isMemcpyLike(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *DestE = Call.getArgExpr(0);
  if (!DestE)
    return;

  const MemberExpr *FlexME = nullptr;
  const FieldDecl *FlexFD = nullptr;
  const FieldDecl *CountFD = nullptr;
  const Expr *OwnerBaseExpr = nullptr;

  if (!getFlexArrayAndOwner(DestE, FlexME, FlexFD, CountFD, OwnerBaseExpr))
    return;

  // Resolve the owner region from the base expression (e.g., "event" in "event->data").
  const MemRegion *OwnerReg = getMemRegionFromExpr(OwnerBaseExpr, C);
  if (!OwnerReg)
    return;
  OwnerReg = OwnerReg->getBaseRegion();

  ProgramStateRef State = C.getState();

  // Ensure we have mapping for this owner.
  State = ensureOwnerCountFieldMapping(State, OwnerReg, CountFD);

  const bool *Zeroed = State->get<OwnerZeroedMap>(OwnerReg);
  const bool *CountSet = State->get<OwnerCountSetMap>(OwnerReg);

  // Only warn if we know it's zero-initialized and the counter hasn't been set yet.
  if (Zeroed && *Zeroed && CountSet && !*CountSet) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Write to __counted_by flexible array before setting its length", N);
    R->addRange(DestE->getSourceRange());
    C.emitReport(std::move(R));
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  const MemRegion *Reg = Loc.getAsRegion();
  if (!Reg)
    return;

  // If writing to a field of a struct, see if it is the counted_by counter.
  if (const auto *FR = dyn_cast<FieldRegion>(Reg)) {
    const FieldDecl *AssignedFD = FR->getDecl();
    if (!AssignedFD)
      return;

    const MemRegion *OwnerReg = FR->getSuperRegion();
    if (!OwnerReg)
      return;
    OwnerReg = OwnerReg->getBaseRegion();

    ProgramStateRef State = C.getState();

    // Try to get or compute the CountFD for this owner.
    const FieldDecl *CountFD = nullptr;
    if (const auto *P = State->get<OwnerCountFieldMap>(OwnerReg))
      CountFD = *P;
    if (!CountFD) {
      // Compute from the record declaration (owner's type).
      const RecordDecl *RD = AssignedFD->getParent();
      if (RD) {
        if (const FieldDecl *CFD = findCountFieldFromOwnerRecord(RD)) {
          CountFD = CFD;
          State = State->set<OwnerCountFieldMap>(OwnerReg, CountFD);
        }
      }
      // Initialize CountSet flag to false if absent.
      if (!State->get<OwnerCountSetMap>(OwnerReg)) {
        State = State->set<OwnerCountSetMap>(OwnerReg, false);
      }
    }

    // If the assigned field equals the known counter field, mark it as set.
    if (CountFD && AssignedFD == CountFD) {
      State = State->set<OwnerCountSetMap>(OwnerReg, true);
    }

    C.addTransition(State);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects writes to __counted_by flexible arrays before initializing their length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
