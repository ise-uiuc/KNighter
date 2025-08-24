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
#include "clang/AST/Decl.h"
#include "llvm/ADT/ImmutableSet.h"
#include "llvm/ADT/ImmutableMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <string>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state traits and helper types need to be defined outside of anonymous
// namespaces to avoid specialization issues.
struct PtrAliasMap {};
struct FieldAliasMap {};
struct FreedFieldsMap {};
struct FreedFieldSet {};

// Helper types used in the program state maps/sets.
using FieldIdentity = std::pair<const clang::ento::MemRegion*, const clang::IdentifierInfo*>;
using FieldSet = llvm::ImmutableSet<const clang::IdentifierInfo*>;

// Provide explicit ProgramStateTrait specializations in the correct namespace.
namespace clang {
namespace ento {

template <>
struct ProgramStateTrait<::PtrAliasMap>
    : public ProgramStatePartialTrait<llvm::ImmutableMap<const MemRegion *, const MemRegion *>> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<::FieldAliasMap>
    : public ProgramStatePartialTrait<llvm::ImmutableMap<const MemRegion *, ::FieldIdentity>> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<::FreedFieldSet>
    : public ProgramStatePartialTrait<::FieldSet> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<::FreedFieldsMap>
    : public ProgramStatePartialTrait<llvm::ImmutableMap<const MemRegion *, ::FieldSet>> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

} // namespace ento
} // namespace clang

namespace {

// Known free-like functions.
static const char *KnownFreeLike[] = {
  "kfree", "kvfree", "vfree", "kfree_sensitive"
};

struct CleanupEntry {
  const char *Name;
  unsigned BaseParamIndex;
  llvm::SmallVector<const char*, 4> FreedFields; // field names
};

// Known cleanup helpers that free specific fields of the passed-in base object.
static const CleanupEntry KnownCleanupTable[] = {
  { "bch2_dev_buckets_free", 0, { "buckets_nouse" } }
};

class SAGenTestChecker : public Checker< check::PreCall, check::Bind > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(std::make_unique<BugType>(this, "Double free (overlapping cleanup)", "Memory management")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static const MemRegion *canonicalBase(const MemRegion *R, ProgramStateRef State);
      static const IdentifierInfo *getFieldNameFromMemberExpr(const Expr *E);
      static const MemRegion *getBaseRegionFromMemberExpr(const Expr *E, CheckerContext &C);
      static bool isFreeLike(const CallEvent &Call, CheckerContext &C);
      static const CleanupEntry* matchCleanup(const CallEvent &Call, CheckerContext &C);

      static ProgramStateRef addFreedField(ProgramStateRef State, const MemRegion *Base, const IdentifierInfo *Field, CheckerContext &C);
      static bool wasFieldFreed(ProgramStateRef State, const MemRegion *Base, const IdentifierInfo *Field);

      void reportDoubleFree(const IdentifierInfo *Field, const CallEvent &Call, CheckerContext &C) const;
};

// Return a canonical base region for pointer aliasing.
const MemRegion *SAGenTestChecker::canonicalBase(const MemRegion *R, ProgramStateRef State) {
  if (!R) return nullptr;
  const MemRegion *Base = R->getBaseRegion();
  if (!Base) return nullptr;

  // Follow alias mapping chains (one-directional) to a stable representative.
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (true) {
    if (!Visited.insert(Base).second)
      break;
    const MemRegion *Next = nullptr;
    if (const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Base))
      Next = *NextPtr;
    if (!Next || Next == Base)
      break;
    Base = Next->getBaseRegion();
    if (!Base) break;
  }
  return Base;
}

// Extract field IdentifierInfo* from a MemberExpr contained in E.
const IdentifierInfo *SAGenTestChecker::getFieldNameFromMemberExpr(const Expr *E) {
  if (!E) return nullptr;
  const MemberExpr *ME = dyn_cast<MemberExpr>(E->IgnoreParenCasts());
  if (!ME) return nullptr;
  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD) return nullptr;
  const IdentifierInfo *II = VD->getIdentifier();
  return II;
}

// Compute the base struct region from a MemberExpr contained in E.
const MemRegion *SAGenTestChecker::getBaseRegionFromMemberExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  const MemberExpr *ME = dyn_cast<MemberExpr>(E->IgnoreParenCasts());
  if (!ME) return nullptr;
  const Expr *BaseE = ME->getBase();
  if (!BaseE) return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  if (!MR) return nullptr;

  ProgramStateRef State = C.getState();
  return canonicalBase(MR, State);
}

// Determine if a call is free-like by name.
bool SAGenTestChecker::isFreeLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  for (const char *Name : KnownFreeLike) {
    if (ExprHasName(Origin, Name, C))
      return true;
  }
  return false;
}

// Match a known cleanup helper entry.
const CleanupEntry* SAGenTestChecker::matchCleanup(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return nullptr;
  for (const CleanupEntry &E : KnownCleanupTable) {
    if (ExprHasName(Origin, E.Name, C))
      return &E;
  }
  return nullptr;
}

// Add field to FreedFieldsMap for a base region.
ProgramStateRef SAGenTestChecker::addFreedField(ProgramStateRef State, const MemRegion *Base, const IdentifierInfo *Field, CheckerContext &C) {
  if (!Base || !Field) return State;
  const FieldSet *CurSet = State->get<FreedFieldsMap>(Base);
  auto &FSetFactory = State->get_context<FreedFieldSet>();
  FieldSet S = CurSet ? *CurSet : FSetFactory.getEmptySet();
  if (!S.contains(Field)) {
    S = FSetFactory.add(S, Field);
    State = State->set<FreedFieldsMap>(Base, S);
  }
  return State;
}

// Check if a field was already freed for a base region.
bool SAGenTestChecker::wasFieldFreed(ProgramStateRef State, const MemRegion *Base, const IdentifierInfo *Field) {
  if (!Base || !Field) return false;
  const FieldSet *CurSet = State->get<FreedFieldsMap>(Base);
  if (!CurSet) return false;
  return CurSet->contains(Field);
}

// Emit a report.
void SAGenTestChecker::reportDoubleFree(const IdentifierInfo *Field, const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  std::string Msg;
  if (Field)
    Msg = ("Double free of struct field '" + Field->getName() + "'").str();
  else
    Msg = "Double free of struct field due to overlapping cleanup";
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

// Track aliases and field-to-pointer associations.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) return;

  // Case 1: pointer-to-pointer aliasing: lhs = rhs;
  if (const MemRegion *RHSReg = Val.getAsRegion()) {
    RHSReg = RHSReg->getBaseRegion();
    if (RHSReg) {
      const MemRegion *Root = canonicalBase(RHSReg, State);
      if (Root) {
        State = State->set<PtrAliasMap>(LHSReg, Root);
      }
      // Propagate field alias mapping if RHS already maps to a (Base, Field).
      if (const FieldIdentity *RHSFI = State->get<FieldAliasMap>(RHSReg)) {
        State = State->set<FieldAliasMap>(LHSReg, *RHSFI);
      }
      C.addTransition(State);
      return;
    }
  }

  // Case 2: field-to-pointer alias: lhs = base->field (or base.field)
  // We try to find a MemberExpr in the statement.
  if (S) {
    const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(S);
    if (ME) {
      const IdentifierInfo *Field = getFieldNameFromMemberExpr(ME);
      const MemRegion *BaseReg = getBaseRegionFromMemberExpr(ME, C);
      if (Field && BaseReg) {
        State = State->set<FieldAliasMap>(LHSReg, FieldIdentity(BaseReg, Field));
        C.addTransition(State);
        return;
      }
    }
  }
}

// Intercept frees and known cleanup helpers to detect overlapping free of fields.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // 1) Handle free-like functions
  if (isFreeLike(Call, C)) {
    if (Call.getNumArgs() >= 1) {
      const Expr *ArgE = Call.getArgExpr(0);
      const IdentifierInfo *Field = nullptr;
      const MemRegion *BaseReg = nullptr;

      // Try to resolve when the argument is directly a member expression or wraps one.
      if (ArgE) {
        // Prefer a direct MemberExpr attached to the argument.
        const MemberExpr *ME = dyn_cast_or_null<MemberExpr>(findSpecificTypeInChildren<MemberExpr>(ArgE));
        if (!ME) {
          // Sometimes the ArgE itself is a MemberExpr (without extra children).
          ME = dyn_cast<MemberExpr>(ArgE->IgnoreParenCasts());
        }
        if (ME) {
          Field = getFieldNameFromMemberExpr(ME);
          BaseReg = getBaseRegionFromMemberExpr(ME, C);
        }
      }

      // If not a direct member, try resolving via FieldAliasMap for the pointer argument region.
      if (!Field || !BaseReg) {
        SVal ArgVal = Call.getArgSVal(0);
        if (const MemRegion *ArgReg = ArgVal.getAsRegion()) {
          ArgReg = ArgReg->getBaseRegion();
          if (ArgReg) {
            if (const FieldIdentity *FI = State->get<FieldAliasMap>(ArgReg)) {
              BaseReg = canonicalBase(FI->first, State);
              Field = FI->second;
            }
          }
        }
      }

      // If we resolved a (Base, Field), track and detect double free.
      if (Field && BaseReg) {
        if (wasFieldFreed(State, BaseReg, Field)) {
          reportDoubleFree(Field, Call, C);
          return;
        }
        State = addFreedField(State, BaseReg, Field, C);
        C.addTransition(State);
      }
    }
    return;
  }

  // 2) Handle known cleanup helpers
  if (const CleanupEntry *CE = matchCleanup(Call, C)) {
    if (Call.getNumArgs() <= CE->BaseParamIndex)
      return;

    const Expr *BaseArgE = Call.getArgExpr(CE->BaseParamIndex);
    if (!BaseArgE) return;

    const MemRegion *BaseReg = getMemRegionFromExpr(BaseArgE, C);
    if (!BaseReg) return;
    BaseReg = BaseReg->getBaseRegion();
    if (!BaseReg) return;

    BaseReg = canonicalBase(BaseReg, State);
    if (!BaseReg) return;

    // For all fields this helper frees, check and mark.
    for (const char *FName : CE->FreedFields) {
      const IdentifierInfo *FII = &C.getASTContext().Idents.get(FName);
      if (!FII) continue;

      if (wasFieldFreed(State, BaseReg, FII)) {
        reportDoubleFree(FII, Call, C);
        return;
      }
      State = addFreedField(State, BaseReg, FII, C);
    }
    C.addTransition(State);
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of struct fields when a field is freed directly and also by a subsequent cleanup helper",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
