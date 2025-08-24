Refinement Plan:
- Root cause: The checker treated any field freed in a shared error label as suspicious, without distinguishing between fields of function parameters (callee-managed/externally owned) and fields of local on-stack objects (owned by the current function). This led to a false positive in map_write() for kfree(new_map.forward) and kfree(new_map.reverse), which are fields of a local struct new_map.
- Fixes:
  - Gate reporting to only consider frees of fields whose ultimate base is a function parameter (e.g., mt->fc). This matches the buggy pattern and excludes locals like new_map.forward.
  - Strengthen base resolution to walk through nested MemberExpr and unary operators, so we correctly identify the ultimate base (parameter vs. local).
  - Keep existing path-sensitive ownership tracking and label/goto analysis. Add an additional false-positive guard: if the freed field belongs to a local automatic variable, suppress the warning.
  - Keep heuristic suppression when all gotos to the label occur after the earliest local allocator assignment to the field.
  - Improve free-call and allocator-call identification using the CallEvent’s callee identifier when possible, retaining the existing source-text fallback.
- Edge cases/regressions:
  - Deep member chains (e.g., mt->sub.fc) are now handled by walking to the ultimate base.
  - Suppression remains if the argument is definitely NULL (kfree(NULL)).
  - Ownership inference continues to work via AllocSymSet/OwnedRegionSet; no change in API usage, compatible with Clang-18.
  - The target buggy code (kfree(mt->fc) under a shared label) still triggers because the base is a function parameter, and there are multiple gotos into the label before any proven allocation.

Refined Code:
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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: symbols returned by allocators.
REGISTER_SET_WITH_PROGRAMSTATE(AllocSymSet, SymbolRef)
// Program state: regions that this function explicitly owns (assigned an allocator return).
REGISTER_SET_WITH_PROGRAMSTATE(OwnedRegionSet, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
                             check::BeginFunction,
                             check::EndFunction,
                             check::PostCall,
                             check::PreCall,
                             check::Bind> {
  mutable std::unique_ptr<BugType> BT;

  // Per-function: how many gotos target each label.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, unsigned>> FuncLabelIncoming;

  // Per-function: fields directly assigned from allocator calls within this function.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::SmallPtrSet<const FieldDecl*, 16>> FuncLocallyAllocFields;

  // Per-function: for each label, keep the list of concrete goto statements targeting it.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>>> FuncLabelGotos;

  // Per-function: earliest source location where a given FieldDecl is assigned from an allocator call.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const FieldDecl*, SourceLocation>> FuncFieldFirstAllocLoc;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Freeing unowned field in shared error label; possible double free", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to collect labels, gotos, and fields locally assigned from allocators.
  struct FuncInfoCollector : public RecursiveASTVisitor<FuncInfoCollector> {
    CheckerContext &C;
    llvm::DenseMap<const LabelDecl *, const LabelStmt *> LabelMap;
    llvm::SmallVector<const GotoStmt *, 16> Gotos;
    llvm::SmallPtrSet<const FieldDecl*, 16> LocallyAllocFields;
    llvm::DenseMap<const FieldDecl*, SourceLocation> FirstAllocLoc;

    FuncInfoCollector(CheckerContext &Ctx) : C(Ctx) {}

    bool VisitLabelStmt(const LabelStmt *LS) {
      if (const LabelDecl *LD = LS->getDecl())
        LabelMap[LD] = LS;
      return true;
    }

    bool VisitGotoStmt(const GotoStmt *GS) {
      Gotos.push_back(GS);
      return true;
    }

    bool VisitBinaryOperator(const BinaryOperator *BO) {
      if (!BO || !BO->isAssignmentOp())
        return true;

      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      const auto *ME = dyn_cast<MemberExpr>(LHS);
      const auto *CE = dyn_cast<CallExpr>(RHS);
      if (!ME || !CE)
        return true;

      // If RHS call looks like an allocator, record the assigned field and earliest loc.
      if (callExprLooksLikeAllocator(CE, C)) {
        if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          const FieldDecl *CanonFD = FD->getCanonicalDecl();
          LocallyAllocFields.insert(CanonFD);
          SourceLocation CurLoc = BO->getBeginLoc();
          auto It = FirstAllocLoc.find(CanonFD);
          if (It == FirstAllocLoc.end()) {
            FirstAllocLoc[CanonFD] = CurLoc;
          } else {
            const SourceManager &SM = C.getSourceManager();
            // Keep the earliest source location in TU order.
            if (SM.isBeforeInTranslationUnit(CurLoc, It->second))
              It->second = CurLoc;
          }
        }
      }
      return true;
    }

    // Heuristic allocator detection for CallExpr using callee id or source text.
    static bool callExprLooksLikeAllocator(const CallExpr *CE, CheckerContext &C) {
      if (!CE)
        return false;

      static const char *AllocNames[] = {
          "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
          "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
          "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
      };

      // Prefer direct callee name if available.
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        StringRef Name = FD->getName();
        for (const char *N : AllocNames)
          if (Name.equals(N))
            return true;
      }

      // Fallback to source text substring match.
      for (const char *N : AllocNames) {
        if (ExprHasName(CE, N, C))
          return true;
      }
      return false;
    }
  };

  const FunctionDecl *getCurrentFunction(const CheckerContext &C) const {
    const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return D;
  }

  void buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const;

  bool isAllocatorCall(const CallEvent &Call, CheckerContext &C) const;
  bool isFreeLikeCall(const CallEvent &Call, CheckerContext &C) const;

  // Returns true if the reported scenario is a false positive and should be suppressed.
  bool isFalsePositive(const MemberExpr *FreedME, const CallEvent &Call,
                       const LabelStmt *EnclosingLabel, CheckerContext &C) const;

  // Gating heuristic: return the ParmVarDecl if the base of a MemberExpr resolves to a function parameter.
  const ParmVarDecl *getDirectBaseParam(const Expr *BaseE) const;

  // Utility: returns true if ultimate base decl is a local automatic VarDecl.
  bool baseIsLocalAutomatic(const Expr *BaseE) const;

  void reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const {
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  FuncInfoCollector Collector(C);
  Collector.TraverseStmt(const_cast<Stmt *>(Body));

  // Build incoming goto counts and per-label goto lists.
  llvm::DenseMap<const LabelStmt*, unsigned> IncomingCount;
  llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>> LabelToGotos;
  for (const GotoStmt *GS : Collector.Gotos) {
    const LabelDecl *LD = GS->getLabel();
    if (!LD)
      continue;
    auto It = Collector.LabelMap.find(LD);
    if (It == Collector.LabelMap.end())
      continue;
    const LabelStmt *LS = It->second;
    IncomingCount[LS] = IncomingCount.lookup(LS) + 1;
    LabelToGotos[LS].push_back(GS);
  }

  FuncLabelIncoming[FD] = std::move(IncomingCount);
  FuncLocallyAllocFields[FD] = std::move(Collector.LocallyAllocFields);
  FuncLabelGotos[FD] = std::move(LabelToGotos);
  // Store earliest allocator-assignment locations for fields.
  llvm::DenseMap<const FieldDecl*, SourceLocation> Earliest;
  for (const auto &P : Collector.FirstAllocLoc) {
    Earliest[P.first->getCanonicalDecl()] = P.second;
  }
  FuncFieldFirstAllocLoc[FD] = std::move(Earliest);
}

bool SAGenTestChecker::isAllocatorCall(const CallEvent &Call, CheckerContext &C) const {
  if (const IdentifierInfo *II = Call.getCalleeIdentifier()) {
    StringRef Name = II->getName();
    static const char *Names[] = {
        "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
        "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
        "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
    };
    for (const char *N : Names)
      if (Name.equals(N))
        return true;
  }

  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  static const char *NamesTxt[] = {
      "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
      "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
      "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
  };
  for (const char *N : NamesTxt) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isFreeLikeCall(const CallEvent &Call, CheckerContext &C) const {
  if (const IdentifierInfo *II = Call.getCalleeIdentifier()) {
    StringRef Name = II->getName();
    static const char *Names[] = {"kfree", "kvfree", "vfree"};
    for (const char *N : Names)
      if (Name.equals(N))
        return true;
  }

  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  static const char *NamesTxt[] = {"kfree", "kvfree", "vfree"};
  for (const char *N : NamesTxt) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Build per-function metadata (labels and locally-allocated fields).
  buildPerFunctionInfo(FD, C);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Clean per-function metadata.
  FuncLabelIncoming.erase(FD);
  FuncLocallyAllocFields.erase(FD);
  FuncLabelGotos.erase(FD);
  FuncFieldFirstAllocLoc.erase(FD);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isAllocatorCall(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef RetSym = Ret.getAsSymbol();
  if (!RetSym)
    return;

  if (!State->contains<AllocSymSet>(RetSym)) {
    State = State->add<AllocSymSet>(RetSym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstReg = Loc.getAsRegion();
  if (!DstReg)
    return;

  SymbolRef RHSym = Val.getAsSymbol();
  if (!RHSym)
    return;

  if (State->contains<AllocSymSet>(RHSym)) {
    // Mark the precise region as owned.
    if (!State->contains<OwnedRegionSet>(DstReg)) {
      State = State->add<OwnedRegionSet>(DstReg);
    }
    // Also mark the base region to be robust against field/base conversions.
    const MemRegion *Base = DstReg->getBaseRegion();
    if (Base && !State->contains<OwnedRegionSet>(Base)) {
      State = State->add<OwnedRegionSet>(Base);
    }
    C.addTransition(State);
  }
}

static const Expr *stripCastsAndUnary(const Expr *E) {
  while (true) {
    E = E->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      UnaryOperatorKind Op = UO->getOpcode();
      if (Op == UO_Deref || Op == UO_AddrOf) {
        E = UO->getSubExpr();
        continue;
      }
    }
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
      E = ASE->getBase();
      continue;
    }
    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      E = ME->getBase();
      continue;
    }
    break;
  }
  return E;
}

const ParmVarDecl *SAGenTestChecker::getDirectBaseParam(const Expr *BaseE) const {
  if (!BaseE)
    return nullptr;

  const Expr *E = stripCastsAndUnary(BaseE);
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<ParmVarDecl>(DRE->getDecl());
  }
  return nullptr;
}

bool SAGenTestChecker::baseIsLocalAutomatic(const Expr *BaseE) const {
  if (!BaseE)
    return false;
  const Expr *E = stripCastsAndUnary(BaseE);
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      return VD->hasLocalStorage();
    }
  }
  return false;
}

bool SAGenTestChecker::isFalsePositive(const MemberExpr *FreedME,
                                       const CallEvent &Call,
                                       const LabelStmt *EnclosingLabel,
                                       CheckerContext &C) const {
  // 0) If the field clearly belongs to a local automatic variable (e.g., new_map.forward),
  //    this function owns it, and freeing in a shared label is typically fine.
  if (FreedME) {
    if (baseIsLocalAutomatic(FreedME->getBase()))
      return true;
  }

  // 1) If the argument is definitely the literal NULL at this point, kfree(NULL) is a no-op.
  SVal ArgVal = C.getSVal(Call.getArgExpr(0));
  if (ArgVal.isZeroConstant())
    return true;

  // 2) If this function path-sensitively owns the region (or its base), don't warn on this path.
  const MemRegion *FreedReg = getMemRegionFromExpr(Call.getArgExpr(0), C);
  if (FreedReg) {
    const MemRegion *Base = FreedReg->getBaseRegion();
    ProgramStateRef State = C.getState();
    if (State->contains<OwnedRegionSet>(FreedReg) ||
        (Base && State->contains<OwnedRegionSet>(Base))) {
      return true;
    }
  }

  // 3) If all incoming gotos to this label lexically occur after the earliest allocator
  //    assignment to this field in the same function, then the shared label is safe.
  const FunctionDecl *FD = getCurrentFunction(C);
  if (FD && FreedME) {
    const FieldDecl *FreedFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (FreedFD) {
      const FieldDecl *CanonFD = FreedFD->getCanonicalDecl();

      auto AllocItF = FuncFieldFirstAllocLoc.find(FD);
      auto GotoItF  = FuncLabelGotos.find(FD);
      if (AllocItF != FuncFieldFirstAllocLoc.end() &&
          GotoItF  != FuncLabelGotos.end()) {
        auto AllocIt = AllocItF->second.find(CanonFD);
        auto GLabelIt = GotoItF->second.find(EnclosingLabel);
        if (AllocIt != AllocItF->second.end() &&
            GLabelIt != GotoItF->second.end()) {
          SourceLocation AllocLoc = AllocIt->second;
          const auto &Gotos = GLabelIt->second;
          if (!Gotos.empty()) {
            const SourceManager &SM = C.getSourceManager();
            bool AnyBefore = false;
            for (const GotoStmt *GS : Gotos) {
              SourceLocation GLoc = GS->getGotoLoc();
              // If a goto appears before the allocator assignment, there exists
              // a path to the label prior to ownership -> potential bug.
              if (SM.isBeforeInTranslationUnit(GLoc, AllocLoc)) {
                AnyBefore = true;
                break;
              }
            }
            if (!AnyBefore) {
              // All incoming gotos occur after allocator assignment to this field.
              // The shared label free is consistent with local ownership.
              return true;
            }
          }
        }
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing unowned field in shared error label; possible double free", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isFreeLikeCall(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return;

  // Only consider freeing a struct/union field like mt->fc.
  const Expr *Stripped = ArgE->IgnoreParenImpCasts();
  const auto *FreedME = dyn_cast<MemberExpr>(Stripped);
  if (!FreedME)
    return;

  // Gate: Only warn when the freed field belongs (ultimately) to a function parameter.
  // This matches the target buggy pattern (e.g., mt->fc) and suppresses common cleanup
  // of local/private state (e.g., new_map.forward).
  const Expr *BaseE = FreedME->getBase();
  const ParmVarDecl *BaseParam = getDirectBaseParam(BaseE);
  if (!BaseParam)
    return;

  // Determine if the call is under a label with multiple incoming gotos.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const LabelStmt *EnclosingLabel = findSpecificTypeInParents<LabelStmt>(Origin, C);
  if (!EnclosingLabel)
    return;

  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;

  auto Fit = FuncLabelIncoming.find(FD);
  if (Fit == FuncLabelIncoming.end())
    return;

  const auto &IncomingMap = Fit->second;
  auto Lit = IncomingMap.find(EnclosingLabel);
  unsigned Count = (Lit == IncomingMap.end()) ? 0u : Lit->second;

  // Only warn for shared labels (2 or more incoming gotos).
  if (Count < 2)
    return;

  // Suppress known false positives (NULL frees, locally-owned, or lexically-safe labels).
  if (isFalsePositive(FreedME, Call, EnclosingLabel, C))
    return;

  reportFreeUnownedInSharedLabel(Call, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing unowned fields in shared error labels that may cause double free",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
