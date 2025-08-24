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
#include "llvm/ADT/SmallPtrSet.h"
#include <memory>

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

  // Per-function: fields directly assigned from ANY function call within this function.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::SmallPtrSet<const FieldDecl*, 16>> FuncLocallySetByCallFields;

  // Per-function: for each label, keep the list of concrete goto statements targeting it.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>>> FuncLabelGotos;

  // Per-function: earliest source location where a given FieldDecl is assigned from a function call.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const FieldDecl*, SourceLocation>> FuncFieldFirstSetByCallLoc;

  // New: Per-function maps keyed by FieldDecl -> ParmVarDecl -> locations.
  using ParmToLocsMap = llvm::DenseMap<const ParmVarDecl*, llvm::SmallVector<SourceLocation, 4>>;
  using FieldParmLocsMap = llvm::DenseMap<const FieldDecl*, ParmToLocsMap>;

  // Locations of kfree-like calls on param-field.
  mutable llvm::DenseMap<const FunctionDecl*, FieldParmLocsMap> FuncFieldFreeLocs;
  // Locations of param-field = NULL (or 0).
  mutable llvm::DenseMap<const FunctionDecl*, FieldParmLocsMap> FuncFieldNullSetLocs;
  // Locations where param-field is assigned from allocator-like calls.
  mutable llvm::DenseMap<const FunctionDecl*, FieldParmLocsMap> FuncFieldAllocAssignLocs;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Freeing unowned field in shared error label; possible double free", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to perform case-insensitive substring search using lowercase conversion.
  static bool containsLower(StringRef Haystack, StringRef Needle) {
    std::string Lower = Haystack.lower();
    return StringRef(Lower).contains(Needle);
  }

  static bool isPointerType(QualType QT) {
    return QT->isPointerType() || QT->isAnyPointerType();
  }

  // is NULL literal or an integer zero after ignoring casts.
  static bool isExplicitNullExpr(const Expr *E) {
    if (!E) return false;
    E = E->IgnoreParenImpCasts();
    if (isa<GNUNullExpr>(E)) return true;
#if CLANG_VERSION_MAJOR >= 4
    if (isa<CXXNullPtrLiteralExpr>(E)) return true;
#endif
    if (const auto *IL = dyn_cast<IntegerLiteral>(E))
      return IL->getValue().isZero();
    return false;
  }

  // Helper to collect labels, gotos, and fields locally assigned from function calls,
  // as well as free/nullset/allocator-assign locations per (param, field).
  struct FuncInfoCollector : public RecursiveASTVisitor<FuncInfoCollector> {
    CheckerContext &C;
    llvm::DenseMap<const LabelDecl *, const LabelStmt *> LabelMap;
    llvm::SmallVector<const GotoStmt *, 16> Gotos;
    llvm::SmallPtrSet<const FieldDecl*, 16> LocallySetByCallFields;
    llvm::DenseMap<const FieldDecl*, SourceLocation> FirstSetLoc;

    FieldParmLocsMap FreeLocs;
    FieldParmLocsMap NullSetLocs;
    FieldParmLocsMap AllocAssignLocs;

    // New: Variables assigned from allocator-like calls: VarDecl -> locations.
    llvm::DenseMap<const VarDecl*, llvm::SmallVector<SourceLocation, 4>> VarAllocLocs;

    FuncInfoCollector(CheckerContext &Ctx) : C(Ctx) {}

    static const Expr *ignoreCastsAndWrappers(const Expr *E) {
      if (!E) return nullptr;
      const Expr *Cur = E->IgnoreParenImpCasts();
      while (true) {
        if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
          if (UO->getOpcode() == UO_AddrOf || UO->getOpcode() == UO_Deref) {
            Cur = UO->getSubExpr()->IgnoreParenImpCasts();
            continue;
          }
        }
        if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Cur)) {
          Cur = ASE->getBase()->IgnoreParenImpCasts();
          continue;
        }
        break;
      }
      return Cur->IgnoreParenImpCasts();
    }

    static bool isExplicitNullExprLocal(const Expr *E) {
      if (!E) return false;
      E = E->IgnoreParenImpCasts();
      if (isa<GNUNullExpr>(E)) return true;
#if CLANG_VERSION_MAJOR >= 4
      if (isa<CXXNullPtrLiteralExpr>(E)) return true;
#endif
      if (const auto *IL = dyn_cast<IntegerLiteral>(E))
        return IL->getValue().isZero();
      return false;
    }

    static const MemberExpr* getMemberExprFromExpr(const Expr *E) {
      const Expr *S = ignoreCastsAndWrappers(E);
      return dyn_cast_or_null<MemberExpr>(S);
    }

    // Resolve base to a function parameter if possible.
    static const ParmVarDecl *getDirectBaseParam(const Expr *BaseE) {
      if (!BaseE) return nullptr;
      const Expr *E = BaseE;
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
        break;
      }
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        return dyn_cast<ParmVarDecl>(DRE->getDecl());
      }
      return nullptr;
    }

    static bool callExprLooksLikeAllocator(const CallExpr *CE, CheckerContext &C) {
      if (!CE)
        return false;

      static const char *AllocNames[] = {
          "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
          "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
          "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
      };

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

    static bool getFreeLikeArgIndex(const CallExpr *CE, unsigned &OutIdx) {
      OutIdx = 0;
      if (!CE) return false;
      const FunctionDecl *FD = CE->getDirectCallee();
      if (!FD) return false;
      StringRef Name = FD->getName();
      if (Name.equals("kfree") || Name.equals("kvfree")) {
        if (CE->getNumArgs() >= 1) { OutIdx = 0; return true; }
      } else if (Name.equals("devm_kfree")) {
        if (CE->getNumArgs() >= 2) { OutIdx = 1; return true; }
      }
      return false;
    }

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
      const SourceLocation CurLoc = BO->getBeginLoc();
      const SourceManager &SM = C.getSourceManager();

      // Track fields assigned from call expressions (potential allocators),
      // and record the earliest location.
      if (const auto *ME = dyn_cast<MemberExpr>(LHS)) {
        const ValueDecl *VD = ME->getMemberDecl();
        if (const auto *FD = dyn_cast_or_null<FieldDecl>(VD)) {
          const ParmVarDecl *BaseP = getDirectBaseParam(ME->getBase());
          if (BaseP) {
            // NULL set tracking.
            if (isExplicitNullExprLocal(RHS)) {
              NullSetLocs[FD->getCanonicalDecl()][BaseP].push_back(CurLoc);
            }
            // Allocator-assignment tracking when RHS is a call.
            if (const auto *RCE = dyn_cast<CallExpr>(RHS)) {
              if (callExprLooksLikeAllocator(RCE, C)) {
                AllocAssignLocs[FD->getCanonicalDecl()][BaseP].push_back(CurLoc);
              }
            }
            // New: Allocator-assignment tracking when RHS is a variable previously
            //       assigned from an allocator in this function.
            if (const auto *RDRE = dyn_cast<DeclRefExpr>(RHS)) {
              if (const auto *RVD = dyn_cast<VarDecl>(RDRE->getDecl())) {
                auto It = VarAllocLocs.find(RVD->getCanonicalDecl());
                if (It != VarAllocLocs.end()) {
                  const auto &ALocs = It->second;
                  bool HasPriorAlloc = false;
                  for (SourceLocation LA : ALocs) {
                    if (SM.isBeforeInTranslationUnit(LA, CurLoc)) {
                      HasPriorAlloc = true;
                      break;
                    }
                  }
                  if (HasPriorAlloc) {
                    AllocAssignLocs[FD->getCanonicalDecl()][BaseP].push_back(CurLoc);
                  }
                }
              }
            }
          }
        }
      }

      // Track variables assigned from allocator calls: var = kmalloc(...);
      if (const auto *LDRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (const auto *LVD = dyn_cast<VarDecl>(LDRE->getDecl())) {
          if (const auto *RCE = dyn_cast<CallExpr>(RHS)) {
            if (callExprLooksLikeAllocator(RCE, C)) {
              VarAllocLocs[LVD->getCanonicalDecl()].push_back(CurLoc);
            }
          }
        }
      }

      // Existing tracking of "assigned from any call" for other heuristics.
      const auto *ME = dyn_cast<MemberExpr>(LHS);
      const auto *CE = dyn_cast<CallExpr>(RHS);
      if (!ME || !CE)
        return true;

      // Only consider assignments of pointer-typed fields from function calls.
      const ValueDecl *VD = ME->getMemberDecl();
      if (!VD)
        return true;
      QualType LT = VD->getType();
      if (!isPointerType(LT))
        return true;

      if (const auto *FD = dyn_cast<FieldDecl>(VD)) {
        const FieldDecl *CanonFD = FD->getCanonicalDecl();
        LocallySetByCallFields.insert(CanonFD);
        auto It = FirstSetLoc.find(CanonFD);
        if (It == FirstSetLoc.end()) {
          FirstSetLoc[CanonFD] = CurLoc;
        } else {
          if (SM.isBeforeInTranslationUnit(CurLoc, It->second))
            It->second = CurLoc;
        }
      }
      return true;
    }

    bool VisitCallExpr(const CallExpr *CE) {
      unsigned ArgIdx = 0;
      if (!getFreeLikeArgIndex(CE, ArgIdx))
        return true;

      if (ArgIdx >= CE->getNumArgs())
        return true;

      const Expr *ArgE = CE->getArg(ArgIdx);
      const MemberExpr *ME = getMemberExprFromExpr(ArgE);
      if (!ME)
        return true;

      const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
      if (!FD)
        return true;

      const ParmVarDecl *BaseP = getDirectBaseParam(ME->getBase());
      if (!BaseP)
        return true;

      FreeLocs[FD->getCanonicalDecl()][BaseP].push_back(CE->getBeginLoc());
      return true;
    }
  };

  const FunctionDecl *getCurrentFunction(const CheckerContext &C) const {
    const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return D;
  }

  void buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const;

  bool isAllocatorCall(const CallEvent &Call, CheckerContext &C) const;

  // Identify free-like functions and which parameter indices are the freed pointers.
  bool getFreeLikeParamIndices(const CallEvent &Call,
                               llvm::SmallVectorImpl<unsigned> &Idxs) const;

  // Returns true if the reported scenario is a false positive and should be suppressed.
  bool isFalsePositive(const Expr *FreedArgE, const MemberExpr *FreedME,
                       const ParmVarDecl *BaseParam,
                       const CallEvent &Call, const LabelStmt *EnclosingLabel,
                       CheckerContext &C) const;

  // Gating heuristic: return the ParmVarDecl if the base of a MemberExpr resolves directly to a function parameter.
  const ParmVarDecl *getDirectBaseParam(const Expr *BaseE) const;

  // Additional gating: check whether the target label has any error-like incoming goto.
  bool labelHasErrorishIncoming(const FunctionDecl *FD, const LabelStmt *LS, CheckerContext &C) const;

  // Helpers for "error-ish" classification.
  bool labelNameLooksErrorish(const LabelStmt *LS) const;
  bool gotoLooksErrorish(const GotoStmt *GS, CheckerContext &C) const;
  bool condLooksErrorish(const Expr *Cond, CheckerContext &C) const;
  const Expr *stripWrapperCalls(const Expr *E, CheckerContext &C) const;

  // New: immediate post-label nullification check to robustly suppress FPs like adf_rl_start().
  bool isImmediateNullificationAfterLabel(const LabelStmt *LS,
                                          const FieldDecl *FD,
                                          const ParmVarDecl *BaseP,
                                          CheckerContext &C) const;

  bool sameFieldAndBase(const MemberExpr *ME,
                        const FieldDecl *FD,
                        const ParmVarDecl *BaseP) const;

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
  FuncLocallySetByCallFields[FD] = std::move(Collector.LocallySetByCallFields);
  FuncLabelGotos[FD] = std::move(LabelToGotos);

  // Store earliest assignment-from-call locations for fields.
  llvm::DenseMap<const FieldDecl*, SourceLocation> Earliest;
  for (const auto &P : Collector.FirstSetLoc) {
    Earliest[P.first->getCanonicalDecl()] = P.second;
  }
  FuncFieldFirstSetByCallLoc[FD] = std::move(Earliest);

  // Store fine-grained per-(param,field) location data for FP suppression.
  FuncFieldFreeLocs[FD] = std::move(Collector.FreeLocs);
  FuncFieldNullSetLocs[FD] = std::move(Collector.NullSetLocs);
  FuncFieldAllocAssignLocs[FD] = std::move(Collector.AllocAssignLocs);
}

bool SAGenTestChecker::isAllocatorCall(const CallEvent &Call, CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;
  StringRef Name = FD->getName();

  static const char *Names[] = {
      "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
      "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
      "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
  };
  for (const char *N : Names) {
    if (Name.equals(N))
      return true;
  }
  return false;
}

bool SAGenTestChecker::getFreeLikeParamIndices(const CallEvent &Call,
                                               llvm::SmallVectorImpl<unsigned> &Idxs) const {
  Idxs.clear();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;

  StringRef Name = FD->getName();
  // Only consider heap-free routines tied to the target pattern; exclude vfree().
  if (Name.equals("kfree") || Name.equals("kvfree")) {
    if (Call.getNumArgs() >= 1)
      Idxs.push_back(0);
  } else if (Name.equals("devm_kfree")) {
    if (Call.getNumArgs() >= 2)
      Idxs.push_back(1); // freed pointer is the second argument
  } else {
    return false;
  }
  return !Idxs.empty();
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Build per-function metadata (labels and locally-assigned-from-call fields).
  buildPerFunctionInfo(FD, C);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Clean per-function metadata.
  FuncLabelIncoming.erase(FD);
  FuncLocallySetByCallFields.erase(FD);
  FuncLabelGotos.erase(FD);
  FuncFieldFirstSetByCallLoc.erase(FD);
  FuncFieldFreeLocs.erase(FD);
  FuncFieldNullSetLocs.erase(FD);
  FuncFieldAllocAssignLocs.erase(FD);
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

const ParmVarDecl *SAGenTestChecker::getDirectBaseParam(const Expr *BaseE) const {
  if (!BaseE)
    return nullptr;

  const Expr *E = BaseE;
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
    break;
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<ParmVarDecl>(DRE->getDecl());
  }
  return nullptr;
}

const Expr *SAGenTestChecker::stripWrapperCalls(const Expr *E, CheckerContext &C) const {
  const Expr *Cur = E ? E->IgnoreParenImpCasts() : nullptr;
  while (const auto *CE = dyn_cast_or_null<CallExpr>(Cur)) {
    const FunctionDecl *FD = CE->getDirectCallee();
    StringRef Name = FD ? FD->getName() : StringRef();
    // Common kernel wrappers/macros lowered as calls we want to peel.
    if (Name.equals("unlikely") || Name.equals("likely") ||
        Name.equals("__builtin_expect")) {
      if (CE->getNumArgs() > 0) {
        Cur = CE->getArg(0)->IgnoreParenImpCasts();
        continue;
      }
    }
    break;
  }
  return Cur ? Cur->IgnoreParenImpCasts() : nullptr;
}

bool SAGenTestChecker::condLooksErrorish(const Expr *Cond, CheckerContext &C) const {
  if (!Cond)
    return false;

  const Expr *E = stripWrapperCalls(Cond, C);
  if (!E)
    return false;

  // if (ret) or if (!ret) patterns where 'ret' is a typical error code variable.
  auto LooksLikeErrVar = [](StringRef N) {
    return N.equals("ret") || N.equals("rc") || N.equals("err") || N.equals("error") || N.equals("status");
  };

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (LooksLikeErrVar(VD->getName()))
        return true;
    }
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      if (const auto *D = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts()))
        if (const auto *VD = dyn_cast<VarDecl>(D->getDecl()))
          if (LooksLikeErrVar(VD->getName()))
            return true;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->isComparisonOp() || BO->getOpcode() == BO_NE || BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      auto IsZeroOrNegConst = [](const Expr *X) -> bool {
        if (const auto *IL = dyn_cast<IntegerLiteral>(X)) {
          return IL->getValue().isZero(); // zero
        }
        return false;
      };
      auto IsErrVar = [&](const Expr *X) -> bool {
        if (const auto *DR = dyn_cast<DeclRefExpr>(X))
          if (const auto *VD = dyn_cast<VarDecl>(DR->getDecl()))
            return LooksLikeErrVar(VD->getName());
        return false;
      };
      // ret != 0, ret < 0, 0 != ret, etc.
      if ((IsErrVar(L) && IsZeroOrNegConst(R)) || (IsErrVar(R) && IsZeroOrNegConst(L)))
        return true;
    }
  }

  // if (IS_ERR(ptr)) or IS_ERR_OR_NULL(ptr)
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      StringRef N = FD->getName();
      if (N.equals("IS_ERR") || N.equals("IS_ERR_OR_NULL") || N.equals("IS_ERR_VALUE"))
        return true;
    } else {
      // Fallback: text search in the expression for kernel helpers.
      if (ExprHasName(E, "IS_ERR", C) || ExprHasName(E, "IS_ERR_OR_NULL", C) || ExprHasName(E, "IS_ERR_VALUE", C))
        return true;
    }
  }

  return false;
}

bool SAGenTestChecker::labelNameLooksErrorish(const LabelStmt *LS) const {
  if (!LS || !LS->getDecl())
    return false;
  StringRef N = LS->getDecl()->getName();
  // Common error cleanup labels in kernel code.
  return containsLower(N, "err") || containsLower(N, "error") ||
         containsLower(N, "fail") || containsLower(N, "free") ||
         containsLower(N, "cleanup") || containsLower(N, "out_err");
}

bool SAGenTestChecker::gotoLooksErrorish(const GotoStmt *GS, CheckerContext &C) const {
  if (!GS)
    return false;

  // If there's an enclosing if-statement, examine its condition.
  if (const IfStmt *IS = findSpecificTypeInParents<IfStmt>(GS, C)) {
    if (const Expr *Cond = IS->getCond()) {
      if (condLooksErrorish(Cond, C))
        return true;
    }
  }

  // Otherwise, fall back to label name being errorish.
  const LabelDecl *LD = GS->getLabel();
  if (LD) {
    StringRef N = LD->getName();
    if (containsLower(N, "err") || containsLower(N, "error") ||
        containsLower(N, "fail") || containsLower(N, "free") ||
        containsLower(N, "cleanup") || containsLower(N, "out_err"))
      return true;
  }
  return false;
}

bool SAGenTestChecker::labelHasErrorishIncoming(const FunctionDecl *FD, const LabelStmt *LS, CheckerContext &C) const {
  if (!FD || !LS)
    return false;
  auto ItF = FuncLabelGotos.find(FD);
  if (ItF == FuncLabelGotos.end())
    return false;
  auto It = ItF->second.find(LS);
  if (It == ItF->second.end())
    return false;

  // If label name looks errorish, that's sufficient.
  if (labelNameLooksErrorish(LS))
    return true;

  const auto &Gotos = It->second;
  for (const GotoStmt *GS : Gotos) {
    if (gotoLooksErrorish(GS, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::sameFieldAndBase(const MemberExpr *ME,
                                        const FieldDecl *FD,
                                        const ParmVarDecl *BaseP) const {
  if (!ME || !FD || !BaseP)
    return false;
  const auto *MEFD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!MEFD)
    return false;
  if (MEFD->getCanonicalDecl() != FD->getCanonicalDecl())
    return false;
  const ParmVarDecl *MEBaseP = getDirectBaseParam(ME->getBase());
  return MEBaseP && MEBaseP->getCanonicalDecl() == BaseP->getCanonicalDecl();
}

// Robust, local suppression: If the free is the first statement in a label and the next
// one or two statements set the same param->field to NULL, consider it a safe cleanup idiom.
bool SAGenTestChecker::isImmediateNullificationAfterLabel(const LabelStmt *LS,
                                                          const FieldDecl *FD,
                                                          const ParmVarDecl *BaseP,
                                                          CheckerContext &C) const {
  if (!LS || !FD || !BaseP)
    return false;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(LS, C);
  if (!CS)
    return false;

  // Locate LS inside its compound.
  bool FoundLabel = false;
  unsigned LookAhead = 0;
  for (const Stmt *Child : CS->body()) {
    if (!FoundLabel) {
      if (Child == LS)
        FoundLabel = true;
      continue;
    }
    // We are after the label.
    if (!Child)
      break;
    // Stop scanning if we hit another label or a return.
    if (isa<LabelStmt>(Child) || isa<ReturnStmt>(Child))
      break;
    // Be conservative: only look ahead a couple of statements.
    if (LookAhead++ >= 2)
      break;

    // Try to find an assignment in this statement subtree.
    const BinaryOperator *BO = findSpecificTypeInChildren<BinaryOperator>(Child);
    if (!BO || !BO->isAssignmentOp())
      continue;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const auto *LME = dyn_cast<MemberExpr>(LHS);
    if (!LME)
      continue;

    const Expr *RHS = BO->getRHS();
    if (!isExplicitNullExpr(RHS))
      continue;

    if (sameFieldAndBase(LME, FD, BaseP))
      return true;
  }

  return false;
}

bool SAGenTestChecker::isFalsePositive(const Expr *FreedArgE,
                                       const MemberExpr *FreedME,
                                       const ParmVarDecl *BaseParam,
                                       const CallEvent &Call,
                                       const LabelStmt *EnclosingLabel,
                                       CheckerContext &C) const {
  // 0) If the label does not look like an error path for any of its incoming gotos,
  //    this is very likely a normal cleanup label (e.g. "out") -> suppress.
  const FunctionDecl *FD = getCurrentFunction(C);
  if (FD && EnclosingLabel && !labelHasErrorishIncoming(FD, EnclosingLabel, C))
    return true;

  // 0.5) Immediate post-label nullification suppression.
  // If the very next statements after the label assign "param->field = NULL", accept the cleanup.
  if (EnclosingLabel && FreedME && BaseParam) {
    const auto *FDField = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (FDField && isImmediateNullificationAfterLabel(EnclosingLabel, FDField->getCanonicalDecl(),
                                                      BaseParam, C)) {
      return true;
    }
  }

  // 1) If the argument is definitely the literal NULL at this point, kfree(NULL) is a no-op.
  if (FreedArgE) {
    SVal ArgVal = C.getSVal(FreedArgE);
    if (ArgVal.isZeroConstant())
      return true;
  }

  // 2) If this function path-sensitively owns the region (or its base), don't warn on this path.
  if (FreedArgE) {
    const MemRegion *FreedReg = getMemRegionFromExpr(FreedArgE, C);
    if (FreedReg) {
      const MemRegion *Base = FreedReg->getBaseRegion();
      ProgramStateRef State = C.getState();
      if (State->contains<OwnedRegionSet>(FreedReg) ||
          (Base && State->contains<OwnedRegionSet>(Base))) {
        return true;
      }
    }
  }

  // 2.4) Intrafunction allocator-assignment suppression (path-insensitive):
  // If this param-field is ever assigned from an allocator anywhere in this function,
  // treat it as locally-owned in general and suppress (avoids FPs when path predicates skip the allocation).
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItAllocF = FuncFieldAllocAssignLocs.find(FD);
      if (ItAllocF != FuncFieldAllocAssignLocs.end()) {
        const auto &AllocMapField = ItAllocF->second;
        auto ItAllocParmMap = AllocMapField.find(CanonFD);
        if (ItAllocParmMap != AllocMapField.end()) {
          auto ItLocs = ItAllocParmMap->second.find(BaseParam);
          if (ItLocs != ItAllocParmMap->second.end()) {
            if (!ItLocs->second.empty())
              return true;
          }
        }
      }
    }
  }

  // 2.5) Intrafunction allocator-assignment suppression (ordered variant):
  // If this same param-field was assigned from an allocator in this function
  // before the current free call, treat it as locally-owned and suppress.
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItAllocF = FuncFieldAllocAssignLocs.find(FD);
      if (ItAllocF != FuncFieldAllocAssignLocs.end()) {
        const auto &AllocMapField = ItAllocF->second;
        auto ItAllocParmMap = AllocMapField.find(CanonFD);
        if (ItAllocParmMap != AllocMapField.end()) {
          auto ItLocs = ItAllocParmMap->second.find(BaseParam);
          if (ItLocs != ItAllocParmMap->second.end()) {
            const llvm::SmallVector<SourceLocation,4> &AllocLocs = ItLocs->second;
            if (!AllocLocs.empty()) {
              const SourceManager &SM = C.getSourceManager();
              SourceLocation CurLoc = Call.getOriginExpr()
                                          ? Call.getOriginExpr()->getBeginLoc()
                                          : Call.getSourceRange().getBegin();
              for (SourceLocation Lalloc : AllocLocs) {
                if (SM.isBeforeInTranslationUnit(Lalloc, CurLoc)) {
                  return true;
                }
              }
            }
          }
        }
      }
    }
  }

  // 2.6) Post-free nullification suppression:
  // If there exists an assignment "param->field = NULL" after this free within the function,
  // consider it a strong cleanup idiom and suppress to avoid FPs.
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItNullF = FuncFieldNullSetLocs.find(FD);
      if (ItNullF != FuncFieldNullSetLocs.end()) {
        const auto &NullMapField = ItNullF->second;
        auto ItNullParmMap = NullMapField.find(CanonFD);
        if (ItNullParmMap != NullMapField.end()) {
          auto ItLocs = ItNullParmMap->second.find(BaseParam);
          if (ItLocs != ItNullParmMap->second.end()) {
            const auto &NullLocs = ItLocs->second;
            if (!NullLocs.empty()) {
              const SourceManager &SM = C.getSourceManager();
              SourceLocation CurLoc = Call.getOriginExpr()
                                          ? Call.getOriginExpr()->getBeginLoc()
                                          : Call.getSourceRange().getBegin();
              for (SourceLocation Lnull : NullLocs) {
                if (SM.isBeforeInTranslationUnit(CurLoc, Lnull)) {
                  return true;
                }
              }
            }
          }
        }
      }
    }
  }

  // 3) AST-based suppression for the "reset and reallocate" idiom:
  //    If there exists a prior free(field) followed by field = NULL (or 0) and then
  //    an allocator assignment to the same field, all before this free -> suppress.
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItFreeF = FuncFieldFreeLocs.find(FD);
      auto ItNullF = FuncFieldNullSetLocs.find(FD);
      auto ItAllocF = FuncFieldAllocAssignLocs.find(FD);
      if (ItFreeF != FuncFieldFreeLocs.end() &&
          ItNullF != FuncFieldNullSetLocs.end() &&
          ItAllocF != FuncFieldAllocAssignLocs.end()) {

        const auto &FreeMapField = ItFreeF->second;
        const auto &NullMapField = ItNullF->second;
        const auto &AllocMapField = ItAllocF->second;

        auto ItFreeParmMap  = FreeMapField.find(CanonFD);
        auto ItNullParmMap  = NullMapField.find(CanonFD);
        auto ItAllocParmMap = AllocMapField.find(CanonFD);

        if (ItFreeParmMap != FreeMapField.end() &&
            ItNullParmMap != NullMapField.end() &&
            ItAllocParmMap != AllocMapField.end()) {
          const auto &FreeVec  = ItFreeParmMap->second.lookup(BaseParam);
          const auto &NullVec  = ItNullParmMap->second.lookup(BaseParam);
          const auto &AllocVec = ItAllocParmMap->second.lookup(BaseParam);

          if (!FreeVec.empty() && !NullVec.empty() && !AllocVec.empty()) {
            const SourceManager &SM = C.getSourceManager();
            SourceLocation CurLoc = Call.getOriginExpr()
                                        ? Call.getOriginExpr()->getBeginLoc()
                                        : Call.getSourceRange().getBegin();
            // Check for free < null < alloc < current
            for (SourceLocation Lfree : FreeVec) {
              if (!SM.isBeforeInTranslationUnit(Lfree, CurLoc))
                continue;
              for (SourceLocation Lnull : NullVec) {
                if (!SM.isBeforeInTranslationUnit(Lfree, Lnull))
                  continue;
                if (!SM.isBeforeInTranslationUnit(Lnull, CurLoc))
                  continue;
                bool HasAllocBetween = false;
                for (SourceLocation Lalloc : AllocVec) {
                  if (SM.isBeforeInTranslationUnit(Lnull, Lalloc) &&
                      SM.isBeforeInTranslationUnit(Lalloc, CurLoc)) {
                    HasAllocBetween = true;
                    break;
                  }
                }
                if (HasAllocBetween) {
                  // All three conditions satisfied for this path -> suppress.
                  return true;
                }
              }
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
  llvm::SmallVector<unsigned, 4> FreeIdxs;
  if (!getFreeLikeParamIndices(Call, FreeIdxs))
    return;

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

  // Only consider shared labels (2 or more incoming gotos).
  if (Count < 2)
    return;

  // Only consider labels that look like error paths.
  if (!labelHasErrorishIncoming(FD, EnclosingLabel, C))
    return;

  // Check each freed argument.
  for (unsigned ArgIndex : FreeIdxs) {
    const Expr *ArgE = Call.getArgExpr(ArgIndex);
    if (!ArgE)
      continue;

    // Only consider freeing a struct/union field like mt->fc.
    const Expr *Stripped = ArgE->IgnoreParenImpCasts();
    const auto *FreedME = dyn_cast<MemberExpr>(Stripped);
    if (!FreedME)
      continue;

    // Only warn when the freed field belongs directly to a function parameter.
    // This matches the target buggy pattern (e.g., mt->fc) and suppresses cleanup of local/private state.
    const Expr *BaseE = FreedME->getBase();
    const ParmVarDecl *BaseParam = getDirectBaseParam(BaseE);
    if (!BaseParam)
      continue;

    // Suppress known false positives (ownership known on path, non-error labels, or reset+realloc/local-alloc idioms).
    if (isFalsePositive(ArgE, FreedME, BaseParam, Call, EnclosingLabel, C))
      continue;

    reportFreeUnownedInSharedLabel(Call, C);
    // One report per call site is sufficient.
    return;
  }
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
