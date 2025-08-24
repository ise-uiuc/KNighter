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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track symbols that are return values of allocation functions that may return NULL.
REGISTER_SET_WITH_PROGRAMSTATE(MaybeNullAllocSyms, SymbolRef)
// Track pointer storage locations (variables, fields, array elements) that currently
// store a maybe-NULL pointer and have not yet been NULL-checked.
REGISTER_SET_WITH_PROGRAMSTATE(UncheckedPtrRegions, const MemRegion *)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::Bind,
        check::BranchCondition,
        check::Location,
        check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Possible NULL dereference", "Memory Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helpers
  bool isMaybeNullAlloc(const CallEvent &Call, CheckerContext &C) const;
  void clearCheckedForExpr(const Expr *E, ProgramStateRef &State, CheckerContext &C) const;
  bool isUncheckedPtrExpr(const Expr *E, ProgramStateRef State, CheckerContext &C) const;

  void reportDeref(const Expr *BaseE, const Stmt *S, CheckerContext &C) const;
  void reportUncheckedArg(const CallEvent &Call, unsigned ArgIdx, CheckerContext &C) const;
};

bool SAGenTestChecker::isMaybeNullAlloc(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Check common kernel allocators that may return NULL
  static const char *Names[] = {
      "devm_kzalloc", "devm_kmalloc", "devm_kcalloc",
      "kzalloc", "kmalloc", "kcalloc"
  };

  for (const char *N : Names) {
    if (ExprHasName(Origin, N, C))
      return true;
  }
  return false;
}

void SAGenTestChecker::clearCheckedForExpr(const Expr *E, ProgramStateRef &State,
                                           CheckerContext &C) const {
  if (!E)
    return;
  const LocationContext *LCtx = C.getLocationContext();
  SVal V = State->getSVal(E, LCtx);

  if (SymbolRef Sym = V.getAsSymbol()) {
    if (State->contains<MaybeNullAllocSyms>(Sym)) {
      State = State->remove<MaybeNullAllocSyms>(Sym);
    }
  }

  // Remove unchecked mark for the storage region if we have it.
  if (const MemRegion *MR = getMemRegionFromExpr(E, C)) {
    MR = MR->getBaseRegion();
    if (MR && State->contains<UncheckedPtrRegions>(MR)) {
      State = State->remove<UncheckedPtrRegions>(MR);
    }
  }
}

bool SAGenTestChecker::isUncheckedPtrExpr(const Expr *E, ProgramStateRef State,
                                          CheckerContext &C) const {
  if (!E)
    return false;

  const LocationContext *LCtx = C.getLocationContext();
  SVal V = State->getSVal(E, LCtx);

  if (SymbolRef Sym = V.getAsSymbol()) {
    if (State->contains<MaybeNullAllocSyms>(Sym))
      return true;
  }

  if (const MemRegion *MR = getMemRegionFromExpr(E, C)) {
    MR = MR->getBaseRegion();
    if (MR && State->contains<UncheckedPtrRegions>(MR))
      return true;
  }

  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (!isMaybeNullAlloc(Call, C))
    return;

  // Mark return symbol as maybe-null allocation result.
  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    State = State->add<MaybeNullAllocSyms>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstR = Loc.getAsRegion();
  if (!DstR) {
    C.addTransition(State);
    return;
  }
  DstR = DstR->getBaseRegion();
  if (!DstR) {
    C.addTransition(State);
    return;
  }

  bool MarkUnchecked = false;

  // Case 1: RHS is a symbol that comes from a maybe-null allocation.
  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (State->contains<MaybeNullAllocSyms>(Sym))
      MarkUnchecked = true;
  }

  // Case 2: If RHS is a region that is itself marked as unchecked storage, propagate.
  if (!MarkUnchecked) {
    if (const MemRegion *SrcR = Val.getAsRegion()) {
      SrcR = SrcR->getBaseRegion();
      if (SrcR && State->contains<UncheckedPtrRegions>(SrcR))
        MarkUnchecked = true;
    }
  }

  if (MarkUnchecked) {
    State = State->add<UncheckedPtrRegions>(DstR);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  CondE = CondE->IgnoreParenCasts();

  // Pattern: if (!ptr) ...
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr();
      if (SubE) {
        SubE = SubE->IgnoreParenCasts();

        // Also handle if (!(ptr = kzalloc(...))) ...
        if (const auto *BO = dyn_cast<BinaryOperator>(SubE)) {
          if (BO->getOpcode() == BO_Assign) {
            const Expr *LHS = BO->getLHS();
            if (LHS) {
              clearCheckedForExpr(LHS, State, C);
            }
          } else {
            clearCheckedForExpr(SubE, State, C);
          }
        } else {
          clearCheckedForExpr(SubE, State, C);
        }
      }
      C.addTransition(State);
      return;
    }
  }

  // Pattern: if (ptr == NULL) or if (ptr != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);

      const Expr *PtrE = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrE = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrE = LHS;

      if (PtrE) {
        clearCheckedForExpr(PtrE, State, C);
        C.addTransition(State);
        return;
      }
    }

    // Pattern: if ((ptr = kzalloc(...))) treat as checked too
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS();
      if (LHS) {
        clearCheckedForExpr(LHS, State, C);
        C.addTransition(State);
        return;
      }
    }
  }

  // Pattern: if (ptr) ...
  // Heuristically consider it a NULL-check and clear.
  {
    SVal V = State->getSVal(CondE, C.getLocationContext());
    if (V.getAs<DefinedSVal>()) {
      clearCheckedForExpr(CondE, State, C);
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportDeref(const Expr *BaseE, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Possible NULL dereference: unchecked result of allocation", N);
  if (S)
    R->addRange(S->getSourceRange());
  if (BaseE)
    R->addRange(BaseE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!S)
    return;

  // Look for ptr->field
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME && ME->isArrow()) {
      const Expr *BaseE = ME->getBase();
      if (isUncheckedPtrExpr(BaseE, State, C)) {
        reportDeref(BaseE, S, C);
        return;
      }
    }
  }

  // Also check if S itself is a MemberExpr
  if (const auto *ME = dyn_cast<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *BaseE = ME->getBase();
      if (isUncheckedPtrExpr(BaseE, State, C)) {
        reportDeref(BaseE, S, C);
        return;
      }
    }
  }

  // Look for *ptr dereference
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (UO && UO->getOpcode() == UO_Deref) {
      const Expr *PtrE = UO->getSubExpr();
      if (isUncheckedPtrExpr(PtrE, State, C)) {
        reportDeref(PtrE, S, C);
        return;
      }
    }
  }
}

void SAGenTestChecker::reportUncheckedArg(const CallEvent &Call, unsigned ArgIdx,
                                          CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked possibly-NULL pointer passed to a function that dereferences it", N);
  R->addRange(Call.getSourceRange());
  if (ArgIdx < Call.getNumArgs())
    R->addRange(Call.getArgExpr(ArgIdx)->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;
    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;
    if (isUncheckedPtrExpr(ArgE, State, C)) {
      reportUncheckedArg(Call, Idx, C);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of possibly-NULL pointers returned by [devm_]k[z/m/c]alloc without NULL checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
