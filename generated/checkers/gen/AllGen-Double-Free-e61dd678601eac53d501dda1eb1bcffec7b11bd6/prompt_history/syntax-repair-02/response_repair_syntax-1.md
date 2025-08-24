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
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/ImmutableSet.h"
#include "llvm/ADT/StringRef.h"
#include <utility>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: for each base object (MemRegion* for the struct pointer variable),
// track which member fields of that object have been freed.
using FieldSetTy = llvm::ImmutableSet<const FieldDecl *>;
REGISTER_MAP_WITH_PROGRAMSTATE(FreedFieldsMap, const MemRegion *, FieldSetTy)

// Program state: simple alias map to canonicalize different variables that point to the same object.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::ASTCodeBody,
                                        check::PostCall,
                                        check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   // Summary: For each function, and for each parameter index,
   // record the set of member fields of that parameter which are directly freed.
   using FieldPtrSet = llvm::SmallPtrSet<const FieldDecl*, 8>;
   using ParamSummary = llvm::DenseMap<unsigned, FieldPtrSet>;
   mutable llvm::DenseMap<const FunctionDecl*, ParamSummary> Summaries;

public:
  SAGenTestChecker() : BT(new BugType(this, "Double free of struct member", "Memory Management")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool isFreeLikeName(StringRef N);
  static bool isFreeLikeCall(const CallEvent &Call, CheckerContext &C);
  static const FieldDecl* getFreedFieldFromArg(const Expr *E);
  static int getParamIndexOfBase(const MemberExpr *ME, const FunctionDecl *CurFD);
  static const MemRegion* canonicalizeRegion(const MemRegion *R, ProgramStateRef State);

  void addFreedFieldToState(const MemRegion *BaseReg, const FieldDecl *FD,
                            const Stmt *Where, CheckerContext &C,
                            StringRef ViaCallee = StringRef()) const;

  void buildSummaryForFunction(const FunctionDecl *FD) const;
};

// ----- Helper implementations -----

bool SAGenTestChecker::isFreeLikeName(StringRef N) {
  return N == "kfree" ||
         N == "kvfree" ||
         N == "vfree" ||
         N == "kfree_sensitive" ||
         N == "kfree_const" ||
         N == "kfree_rcu";
}

bool SAGenTestChecker::isFreeLikeCall(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Use ExprHasName as suggested.
  static const char *Names[] = {
      "kfree", "kvfree", "vfree", "kfree_sensitive", "kfree_const", "kfree_rcu"
  };
  for (const char *N : Names) {
    if (ExprHasName(Origin, N, C))
      return true;
  }
  return false;
}

const FieldDecl* SAGenTestChecker::getFreedFieldFromArg(const Expr *E) {
  if (!E) return nullptr;
  const auto *ME = dyn_cast<MemberExpr>(E->IgnoreParenCasts());
  if (!ME) return nullptr;
  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD) return nullptr;
  return FD->getCanonicalDecl();
}

int SAGenTestChecker::getParamIndexOfBase(const MemberExpr *ME, const FunctionDecl *CurFD) {
  if (!ME || !CurFD) return -1;
  const Expr *Base = ME->getBase();
  if (!Base) return -1;
  Base = Base->IgnoreParenCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE) return -1;
  const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD) return -1;
  if (PVD->getDeclContext() != CurFD)
    return -1;
  return static_cast<int>(PVD->getFunctionScopeIndex());
}

const MemRegion* SAGenTestChecker::canonicalizeRegion(const MemRegion *R, ProgramStateRef State) {
  if (!R) return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  // Follow alias map to root to canonicalize.
  // Guard against cycles.
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break;
    const MemRegion *Next = nullptr;
    if (const MemRegion *const *NextP = State->get<PtrAliasMap>(Cur))
      Next = *NextP;
    if (!Next)
      break;
    Cur = Next->getBaseRegion();
  }
  return Cur;
}

void SAGenTestChecker::addFreedFieldToState(const MemRegion *BaseReg, const FieldDecl *FD,
                                            const Stmt *Where, CheckerContext &C,
                                            StringRef ViaCallee) const {
  if (!BaseReg || !FD) return;
  ProgramStateRef State = C.getState();

  // Access or create the field set for this base region.
  FieldSetTy::Factory &F = State->getStateManager().get_context<FieldSetTy>();
  const FieldSetTy *Existing = State->get<FreedFieldsMap>(BaseReg);
  FieldSetTy Current = Existing ? *Existing : F.getEmptySet();

  // Check for double free
  if (Existing && Existing->contains(FD)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N) return;

    SmallString<128> Msg;
    if (!ViaCallee.empty()) {
      Msg = "Double free of member '";
      Msg += FD->getName();
      Msg += "' via call to '";
      Msg += ViaCallee;
      Msg += "'";
    } else {
      Msg = "Double free of member '";
      Msg += FD->getName();
      Msg += "'";
    }

    auto Rpt = std::make_unique<PathSensitiveBugReport>(*BT, Msg.str(), N);
    if (Where)
      Rpt->addRange(Where->getSourceRange());
    C.emitReport(std::move(Rpt));
    return;
  }

  // Otherwise mark this field as freed for this base object.
  Current = F.add(Current, FD);
  State = State->set<FreedFieldsMap>(BaseReg, Current);
  C.addTransition(State);
}

// ----- Summarization over AST -----

void SAGenTestChecker::buildSummaryForFunction(const FunctionDecl *FD) const {
  if (!FD || !FD->hasBody())
    return;
  // Avoid re-building.
  if (Summaries.find(FD) != Summaries.end())
    return;

  ParamSummary PS;

  // Simple visitor to record "free-like(member-of-parameter)" inside FD.
  class LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
    const FunctionDecl *CurFD;
    ParamSummary &PS;
  public:
    LocalVisitor(const FunctionDecl *F, ParamSummary &S) : CurFD(F), PS(S) {}
    bool VisitCallExpr(CallExpr *CE) {
      if (!CE) return true;
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (!Callee) return true;
      if (!SAGenTestChecker::isFreeLikeName(Callee->getName()))
        return true;
      if (CE->getNumArgs() < 1) return true;

      const Expr *A0 = CE->getArg(0);
      const auto *ME = dyn_cast<MemberExpr>(A0->IgnoreParenCasts());
      if (!ME) return true;

      const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
      if (!FD) return true;
      FD = FD->getCanonicalDecl();

      int Idx = SAGenTestChecker::getParamIndexOfBase(ME, CurFD);
      if (Idx < 0) return true;

      PS[static_cast<unsigned>(Idx)].insert(FD);
      return true;
    }
  };

  if (const Stmt *Body = FD->getBody()) {
    LocalVisitor V(FD, PS);
    V.TraverseStmt(const_cast<Stmt *>(Body));
  }

  Summaries[FD] = std::move(PS);
}

// ----- Checker callbacks -----

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  // Build summary for this function.
  buildSummaryForFunction(FD);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const MemRegion *RHSReg = Val.getAsRegion();
  if (!RHSReg)
    return;
  RHSReg = RHSReg->getBaseRegion();
  if (!RHSReg)
    return;

  // Canonicalize RHS then record alias: LHS -> RHS
  RHSReg = canonicalizeRegion(RHSReg, State);
  if (!RHSReg)
    return;

  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Case A: Direct free-like call on a member, e.g., kfree(obj->field).
  if (isFreeLikeCall(Call, C)) {
    if (Call.getNumArgs() >= 1) {
      const Expr *ArgE = Call.getArgExpr(0);
      const auto *ME = dyn_cast_or_null<MemberExpr>(ArgE ? ArgE->IgnoreParenCasts() : nullptr);
      if (ME) {
        const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
        if (FD) {
          FD = FD->getCanonicalDecl();
          const Expr *BaseE = ME->getBase();
          if (BaseE) {
            const MemRegion *BaseReg = getMemRegionFromExpr(BaseE, C);
            if (BaseReg) {
              BaseReg = canonicalizeRegion(BaseReg, State);
              addFreedFieldToState(BaseReg, FD, Call.getOriginExpr(), C /*Where*/);
            }
          }
        }
      }
    }
  }

  // Case B: Indirect free via a summarized helper function.
  const FunctionDecl *CalleeFD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (CalleeFD) {
    // Ensure we have a summary for the callee (build if body present).
    buildSummaryForFunction(CalleeFD);

    auto It = Summaries.find(CalleeFD);
    if (It != Summaries.end()) {
      const ParamSummary &PS = It->second;
      for (const auto &KV : PS) {
        unsigned ParamIdx = KV.first;
        const FieldPtrSet &Fields = KV.second;
        if (ParamIdx >= Call.getNumArgs())
          continue;

        const Expr *ArgE = Call.getArgExpr(ParamIdx);
        if (!ArgE) continue;

        const MemRegion *BaseReg = getMemRegionFromExpr(ArgE, C);
        if (!BaseReg) continue;
        BaseReg = canonicalizeRegion(BaseReg, State);
        if (!BaseReg) continue;

        StringRef CalleeName;
        if (const IdentifierInfo *II = CalleeFD->getIdentifier())
          CalleeName = II->getName();

        for (const FieldDecl *FD : Fields) {
          addFreedFieldToState(BaseReg, FD, Call.getOriginExpr(), C, CalleeName);
        }
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of struct members via direct or summarized frees",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
