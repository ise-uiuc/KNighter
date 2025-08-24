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
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallString.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: remember members of a specific base object freed along this path.
struct MemberKey {
  const MemRegion *BaseObj;    // base region for the object, e.g., the region for 'ca'
  const FieldDecl *Field;      // field decl for the member, e.g., buckets_nouse

  MemberKey() : BaseObj(nullptr), Field(nullptr) {}
  MemberKey(const MemRegion *B, const FieldDecl *F)
      : BaseObj(B), Field(F) {}

  bool operator==(const MemberKey &O) const {
    return BaseObj == O.BaseObj && Field == O.Field;
  }

  // Provide a strict weak ordering to satisfy potential std::set/smallset fallbacks.
  bool operator<(const MemberKey &O) const {
    if (BaseObj != O.BaseObj)
      return BaseObj < O.BaseObj;
    return Field < O.Field;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(BaseObj);
    ID.AddPointer(Field);
  }
};

REGISTER_SET_WITH_PROGRAMSTATE(FreedMemberSet, MemberKey)

namespace {

// Summary entry: which parameter index and which field is freed by a callee.
struct FreedField {
  unsigned ParamIndex;
  const FieldDecl *Field; // canonical

  FreedField() : ParamIndex(0), Field(nullptr) {}
  FreedField(unsigned I, const FieldDecl *F) : ParamIndex(I), Field(F) {}

  bool operator==(const FreedField &O) const {
    return ParamIndex == O.ParamIndex && Field == O.Field;
  }
};

class SAGenTestChecker
  : public Checker<
        check::PreCall,
        check::ASTCodeBody
      > {
  mutable std::unique_ptr<BugType> BT;

  // Checker-internal summary: For each function, which (param, field) pairs it frees.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::SmallVector<FreedField, 4>> CalleeFreeSummary;

public:
  SAGenTestChecker() : BT(new BugType(this, "Double free of struct member", "Memory Error")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

private:
  // Helpers
  static bool isFreeLike(const CallEvent &Call, CheckerContext &C);
  static bool isFreeLikeCallee(const FunctionDecl *FD);
  static bool extractMemberOnParam(const Expr *E, const FunctionDecl *FD,
                                   unsigned &OutParamIdx, const FieldDecl *&OutFD);
  static bool extractBaseAndFieldFromMember(const Expr *E, CheckerContext &C,
                                            const MemRegion *&OutBaseRegion, const FieldDecl *&OutFD);
  static MemberKey makeKey(const MemRegion *BaseRegion, const FieldDecl *FD);

  void reportDoubleFree(const CallEvent &Call, const FieldDecl *FD, CheckerContext &C) const;

  void buildSummaryForFunction(const FunctionDecl *FD) const;
  const llvm::SmallVector<FreedField, 4> *getOrBuildSummary(const FunctionDecl *FD) const;
};

// Implementation

bool SAGenTestChecker::isFreeLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Per suggestion, use ExprHasName() for name checking.
  if (ExprHasName(Origin, "kfree", C)) return true;
  if (ExprHasName(Origin, "kvfree", C)) return true;
  if (ExprHasName(Origin, "vfree", C)) return true;
  return false;
}

bool SAGenTestChecker::isFreeLikeCallee(const FunctionDecl *FD) {
  if (!FD) return false;
  const IdentifierInfo *ID = FD->getIdentifier();
  if (!ID) return false;
  StringRef Name = ID->getName();
  return Name == "kfree" || Name == "kvfree" || Name == "vfree";
}

// E is expected to be a MemberExpr like P->field or P.field where P is a ParmVarDecl of FD.
bool SAGenTestChecker::extractMemberOnParam(const Expr *E, const FunctionDecl *FD,
                                            unsigned &OutParamIdx, const FieldDecl *&OutFD) {
  if (!E || !FD)
    return false;

  const Expr *IE = E->IgnoreParenImpCasts();
  const auto *ME = dyn_cast<MemberExpr>(IE);
  if (!ME)
    return false;

  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FDDecl = dyn_cast<FieldDecl>(VD);
  if (!FDDecl)
    return false;

  const FieldDecl *CanonFD = cast<FieldDecl>(FDDecl->getCanonicalDecl());

  const Expr *Base = ME->getBase();
  if (!Base)
    return false;

  const Expr *BaseIE = Base->IgnoreParenImpCasts();
  const auto *BaseDRE = dyn_cast<DeclRefExpr>(BaseIE);
  if (!BaseDRE)
    return false;

  const auto *PVD = dyn_cast<ParmVarDecl>(BaseDRE->getDecl());
  if (!PVD)
    return false;

  // Find parameter index
  unsigned Index = 0;
  bool Found = false;
  for (const ParmVarDecl *Param : FD->parameters()) {
    if (Param == PVD) {
      Found = true;
      break;
    }
    ++Index;
  }
  if (!Found)
    return false;

  OutParamIdx = Index;
  OutFD = CanonFD;
  return true;
}

// For direct frees in the current function, extract base region and member field from an expression like 'obj->field'.
bool SAGenTestChecker::extractBaseAndFieldFromMember(const Expr *E, CheckerContext &C,
                                                     const MemRegion *&OutBaseRegion, const FieldDecl *&OutFD) {
  OutBaseRegion = nullptr;
  OutFD = nullptr;
  if (!E)
    return false;

  const Expr *IE = E->IgnoreParenImpCasts();
  const auto *ME = dyn_cast<MemberExpr>(IE);
  if (!ME)
    return false;

  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FDDecl = dyn_cast<FieldDecl>(VD);
  if (!FDDecl)
    return false;

  const FieldDecl *CanonFD = cast<FieldDecl>(FDDecl->getCanonicalDecl());
  const Expr *Base = ME->getBase();
  if (!Base)
    return false;

  // Use the utility to get the region of the base expression.
  const MemRegion *MR = getMemRegionFromExpr(Base, C);
  if (!MR)
    return false;

  MR = MR->getBaseRegion();
  if (!MR)
    return false;

  OutBaseRegion = MR;
  OutFD = CanonFD;
  return true;
}

MemberKey SAGenTestChecker::makeKey(const MemRegion *BaseRegion, const FieldDecl *FD) {
  if (const auto *CanonFD = FD ? cast<FieldDecl>(FD->getCanonicalDecl()) : nullptr) {
    return MemberKey(BaseRegion, CanonFD);
  }
  return MemberKey(BaseRegion, FD);
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, const FieldDecl *FD, CheckerContext &C) const {
  if (!FD)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  llvm::SmallString<128> Msg;
  Msg += "Double free of member '";
  Msg += FD->getName();
  Msg += "'";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

// Build summary for one function: which (param, field) pairs are freed via kfree/kvfree/vfree.
void SAGenTestChecker::buildSummaryForFunction(const FunctionDecl *FD) const {
  if (!FD || !FD->hasBody())
    return;

  const FunctionDecl *CanonFD = FD->getCanonicalDecl();
  if (CalleeFreeSummary.find(CanonFD) != CalleeFreeSummary.end())
    return; // already built

  llvm::SmallVector<FreedField, 4> Summary;
  llvm::SmallSet<std::pair<unsigned, const FieldDecl *>, 8> Seen;

  const Stmt *Body = FD->getBody();
  if (!Body) {
    CalleeFreeSummary[CanonFD] = std::move(Summary);
    return;
  }

  class LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
    const FunctionDecl *FD;
    llvm::SmallVectorImpl<FreedField> &Summary;
    llvm::SmallSet<std::pair<unsigned, const FieldDecl *>, 8> &Seen;

  public:
    LocalVisitor(const FunctionDecl *F,
                 llvm::SmallVectorImpl<FreedField> &S,
                 llvm::SmallSet<std::pair<unsigned, const FieldDecl *>, 8> &Se)
        : FD(F), Summary(S), Seen(Se) {}

    bool VisitCallExpr(CallExpr *CE) {
      if (!CE)
        return true;
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (!SAGenTestChecker::isFreeLikeCallee(Callee))
        return true;

      if (CE->getNumArgs() < 1)
        return true;

      unsigned ParamIdx = 0;
      const FieldDecl *Field = nullptr;
      if (SAGenTestChecker::extractMemberOnParam(CE->getArg(0), FD, ParamIdx, Field)) {
        const FieldDecl *CanonF = Field ? cast<FieldDecl>(Field->getCanonicalDecl()) : nullptr;
        std::pair<unsigned, const FieldDecl *> Key(ParamIdx, CanonF);
        if (!Seen.contains(Key)) {
          Seen.insert(Key);
          Summary.emplace_back(ParamIdx, CanonF);
        }
      }
      return true;
    }
  };

  LocalVisitor V(FD, Summary, Seen);
  V.TraverseStmt(const_cast<Stmt *>(Body));

  CalleeFreeSummary[CanonFD] = std::move(Summary);
}

const llvm::SmallVector<FreedField, 4> *SAGenTestChecker::getOrBuildSummary(const FunctionDecl *FD) const {
  if (!FD)
    return nullptr;
  const FunctionDecl *CanonFD = FD->getCanonicalDecl();
  auto It = CalleeFreeSummary.find(CanonFD);
  if (It != CalleeFreeSummary.end())
    return &It->second;

  // Build on demand if not already built
  if (FD->hasBody())
    buildSummaryForFunction(FD);

  It = CalleeFreeSummary.find(CanonFD);
  if (It != CalleeFreeSummary.end())
    return &It->second;
  return nullptr;
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  if (!FD->hasBody())
    return;

  buildSummaryForFunction(FD);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Case A: Direct free-like calls
  if (isFreeLike(Call, C) && Call.getNumArgs() >= 1) {
    const Expr *Arg0 = Call.getArgExpr(0);
    const MemRegion *BaseReg = nullptr;
    const FieldDecl *FD = nullptr;
    if (extractBaseAndFieldFromMember(Arg0, C, BaseReg, FD)) {
      if (BaseReg) BaseReg = BaseReg->getBaseRegion();
      if (BaseReg && FD) {
        MemberKey K = makeKey(BaseReg, FD);
        if (State->contains<FreedMemberSet>(K)) {
          reportDoubleFree(Call, FD, C);
        }
        State = State->add<FreedMemberSet>(K);
        C.addTransition(State);
      }
    }
    return; // Even if not a member, we only focus on member frees for this checker
  }

  // Case B: Calls to cleanup functions summarized to free certain members
  const FunctionDecl *CalleeFD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!CalleeFD)
    return;

  const auto *Summary = getOrBuildSummary(CalleeFD);
  if (!Summary)
    return;

  for (const FreedField &FF : *Summary) {
    if (FF.ParamIndex >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(FF.ParamIndex);
    if (!ArgE)
      continue;

    const MemRegion *ArgReg = getMemRegionFromExpr(ArgE, C);
    if (!ArgReg)
      continue;

    ArgReg = ArgReg->getBaseRegion();
    if (!ArgReg)
      continue;

    MemberKey K = makeKey(ArgReg, FF.Field);
    if (State->contains<FreedMemberSet>(K)) {
      reportDoubleFree(Call, FF.Field, C);
    }
    State = State->add<FreedMemberSet>(K);
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of struct members across overlapping cleanup routines",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
