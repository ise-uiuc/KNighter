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
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the framework snippet
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);

REGISTER_MAP_WITH_PROGRAMSTATE(Priv2DevMap, const MemRegion*, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(FreedDevs, const MemRegion*)
// Directed map: pointer-typed storage region -> pointee region (optional tracking).
REGISTER_MAP_WITH_PROGRAMSTATE(PtrPointsTo, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::Location,
                                        check::Bind> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use-after-free (net_device private)", "Memory error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name);
  static const MemRegion *getBaseRegionOrSelf(const MemRegion *R);
  static const MemRegion *exprToRegion(const Expr *E, CheckerContext &C);
  static const MemRegion *exprToBaseRegion(const Expr *E, CheckerContext &C);

  static bool devIsFreed(ProgramStateRef State, const MemRegion *DevBase);

  // Return the dev region if R is within some priv region that maps to a dev.
  // OutPrivBase, if non-null, receives the matching priv base region.
  static const MemRegion *findDevForPrivDerivedRegion(ProgramStateRef State,
                                                      const MemRegion *R,
                                                      const MemRegion **OutPrivBase = nullptr);

  // Known functions that synchronously deref work/timer structures.
  static bool knownWorkOrTimerDeref(const CallEvent &Call, CheckerContext &C,
                                    llvm::SmallVectorImpl<unsigned> &OutIdx);

  // AST-only variant used from checkLocation gating (no CallEvent available).
  static bool knownWorkOrTimerDerefCE(const CallExpr *CE, CheckerContext &C,
                                      llvm::SmallVectorImpl<unsigned> &OutIdx);

  static bool isWithinRegion(const MemRegion *R, const MemRegion *Container);

  // FP filter: accessing a pointer-typed lvalue (reading/writing the pointer
  // variable or field itself) is not a dereference of its pointee.
  static bool isPointerLValueRegion(const MemRegion *R);

  // Returns true and fills OutCE+OutArgIdx if S is within argument OutArgIdx
  // of enclosing call expression.
  static bool findEnclosingCallArg(const Stmt *S, CheckerContext &C,
                                   const CallExpr *&OutCE, unsigned &OutArgIdx);

  void reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;
  void reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const;

  // Type-based gating: only consider pointers to work/timer objects.
  static bool isKernelTypeOneOf(const QualType &QT, ArrayRef<StringRef> Names);
  static bool isWorkOrTimerPointerType(const QualType &QT);

  // Attempt to resolve argument pointee region robustly (direct &member, or via
  // a pointer variable tracked by PtrPointsTo, or direct region-valued pointer).
  static const MemRegion *getArgPointeeRegion(const CallEvent &Call, unsigned ArgIdx,
                                              CheckerContext &C, ProgramStateRef State);

  // Heuristic FP filter before reporting.
  static bool isFalsePositive(const CallEvent &Call, unsigned ArgIdx,
                              CheckerContext &C, ProgramStateRef State,
                              const MemRegion *ArgPointee);

  // Resolve pointer variable -> pointee via state if available.
  static const MemRegion *resolvePointerVarToPointee(ProgramStateRef State,
                                                     const MemRegion *MaybePtrVar);
};

bool SAGenTestChecker::callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, Name, C);
}

const MemRegion *SAGenTestChecker::getBaseRegionOrSelf(const MemRegion *R) {
  if (!R) return nullptr;
  const MemRegion *Prev = nullptr;
  const MemRegion *Cur = R;
  while (Cur && Cur != Prev) {
    Prev = Cur;
    Cur = Cur->getBaseRegion();
  }
  return Cur;
}

const MemRegion *SAGenTestChecker::exprToRegion(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  return getMemRegionFromExpr(E, C);
}

const MemRegion *SAGenTestChecker::exprToBaseRegion(const Expr *E, CheckerContext &C) {
  const MemRegion *MR = exprToRegion(E, C);
  if (!MR) return nullptr;
  return getBaseRegionOrSelf(MR);
}

bool SAGenTestChecker::devIsFreed(ProgramStateRef State, const MemRegion *DevBase) {
  if (!DevBase) return false;
  return State->contains<FreedDevs>(DevBase);
}

const MemRegion *SAGenTestChecker::resolvePointerVarToPointee(ProgramStateRef State,
                                                              const MemRegion *MaybePtrVar) {
  if (!MaybePtrVar) return nullptr;
  const auto *TVR = dyn_cast<TypedValueRegion>(MaybePtrVar);
  if (!TVR)
    return MaybePtrVar;

  QualType Ty = TVR->getValueType();
  if (!Ty->isPointerType())
    return MaybePtrVar;

  if (const MemRegion *const *Pointee = State->get<PtrPointsTo>(MaybePtrVar)) {
    return *Pointee;
  }
  return MaybePtrVar;
}

const MemRegion *SAGenTestChecker::findDevForPrivDerivedRegion(ProgramStateRef State,
                                                               const MemRegion *R,
                                                               const MemRegion **OutPrivBase) {
  if (!R) return nullptr;

  // If R is a pointer variable we have a mapping for, resolve to pointee region.
  R = resolvePointerVarToPointee(State, R);

  // Walk up ancestor chain from R, looking for a priv base that we recorded.
  const MemRegion *Cur = R;
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur && Visited.insert(Cur).second) {
    if (const MemRegion *const *DevBase = State->get<Priv2DevMap>(Cur)) {
      if (OutPrivBase)
        *OutPrivBase = Cur;
      return *DevBase;
    }
    if (const auto *SR = dyn_cast<SubRegion>(Cur)) {
      Cur = SR->getSuperRegion();
      continue;
    }
    break;
  }

  if (OutPrivBase)
    *OutPrivBase = nullptr;
  return nullptr;
}

bool SAGenTestChecker::knownWorkOrTimerDeref(const CallEvent &Call, CheckerContext &C,
                                             llvm::SmallVectorImpl<unsigned> &OutIdx) {
  static const char *Names[] = {
      "cancel_work_sync",
      "cancel_delayed_work_sync",
      "flush_work",
      "flush_delayed_work",
      "del_timer_sync",
      "del_timer",
  };

  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Fn = ID->getName();
    for (const char *N : Names) {
      if (Fn.equals(N)) {
        OutIdx.push_back(0);
        return true;
      }
    }
  }

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  for (const char *N : Names) {
    if (ExprHasName(OriginExpr, N, C)) {
      OutIdx.push_back(0);
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::knownWorkOrTimerDerefCE(const CallExpr *CE, CheckerContext &C,
                                               llvm::SmallVectorImpl<unsigned> &OutIdx) {
  if (!CE)
    return false;

  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (const IdentifierInfo *ID = FD->getIdentifier()) {
      StringRef Fn = ID->getName();
      static const char *Names[] = {
          "cancel_work_sync",
          "cancel_delayed_work_sync",
          "flush_work",
          "flush_delayed_work",
          "del_timer_sync",
          "del_timer",
      };
      for (const char *N : Names) {
        if (Fn.equals(N)) {
          OutIdx.push_back(0);
          return true;
        }
      }
    }
  }

  if (const Expr *Callee = CE->getCallee()) {
    static const char *Names[] = {
        "cancel_work_sync",
        "cancel_delayed_work_sync",
        "flush_work",
        "flush_delayed_work",
        "del_timer_sync",
        "del_timer",
    };
    for (const char *N : Names) {
      if (ExprHasName(Callee, N, C)) {
        OutIdx.push_back(0);
        return true;
      }
    }
  }

  return false;
}

bool SAGenTestChecker::isWithinRegion(const MemRegion *R, const MemRegion *Container) {
  if (!R || !Container) return false;
  if (R == Container) return true;
  if (const auto *SR = dyn_cast<SubRegion>(R))
    return SR->isSubRegionOf(Container);
  return false;
}

bool SAGenTestChecker::isPointerLValueRegion(const MemRegion *R) {
  if (!R) return false;
  const auto *TVR = dyn_cast<TypedValueRegion>(R);
  if (!TVR)
    return false;
  QualType Ty = TVR->getValueType();
  return Ty->isPointerType();
}

bool SAGenTestChecker::findEnclosingCallArg(const Stmt *S, CheckerContext &C,
                                            const CallExpr *&OutCE, unsigned &OutArgIdx) {
  OutCE = findSpecificTypeInParents<CallExpr>(S, C);
  if (!OutCE)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const SourceRange SR = S->getSourceRange();
  const SourceLocation SBegin = SR.getBegin();
  const SourceLocation SEnd = SR.getEnd();

  unsigned NumArgs = OutCE->getNumArgs();
  for (unsigned i = 0; i < NumArgs; ++i) {
    const Expr *Arg = OutCE->getArg(i);
    if (!Arg) continue;
    SourceRange AR = Arg->getSourceRange();
    if (!AR.isValid())
      continue;

    SourceLocation ABegin = AR.getBegin();
    SourceLocation AEnd = AR.getEnd();

    bool BeginInside = !SM.isBeforeInTranslationUnit(SBegin, ABegin) &&
                       !SM.isBeforeInTranslationUnit(AEnd, SBegin);
    bool EndInside = !SM.isBeforeInTranslationUnit(SEnd, ABegin) &&
                     !SM.isBeforeInTranslationUnit(AEnd, SEnd);

    if (BeginInside || EndInside) {
      OutArgIdx = i;
      return true;
    }
  }

  return false;
}

void SAGenTestChecker::reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

bool SAGenTestChecker::isKernelTypeOneOf(const QualType &QT, ArrayRef<StringRef> Names) {
  QualType T = QT;
  if (T.isNull())
    return false;

  if (T->isPointerType())
    T = T->getPointeeType();

  T = T.getCanonicalType().getUnqualifiedType();
  const Type *Ty = T.getTypePtrOrNull();
  if (!Ty || !Ty->isRecordType())
    return false;

  const auto RT = T->getAs<RecordType>();
  if (!RT)
    return false;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return false;

  // Kernel uses 'struct work_struct', 'struct delayed_work', 'struct timer_list'.
  IdentifierInfo *II = RD->getIdentifier();
  if (!II)
    return false;

  StringRef Name = II->getName();
  for (StringRef N : Names) {
    if (Name == N)
      return true;
  }
  return false;
}

bool SAGenTestChecker::isWorkOrTimerPointerType(const QualType &QT) {
  if (QT.isNull() || !QT->isPointerType())
    return false;
  static const StringRef Names[] = {"work_struct", "delayed_work", "timer_list"};
  return isKernelTypeOneOf(QT, Names);
}

const MemRegion *SAGenTestChecker::getArgPointeeRegion(const CallEvent &Call, unsigned ArgIdx,
                                                       CheckerContext &C, ProgramStateRef State) {
  if (ArgIdx >= Call.getNumArgs())
    return nullptr;

  const Expr *ArgE = Call.getArgExpr(ArgIdx);
  if (!ArgE)
    return nullptr;

  // Try using symbolic value first: for pointer arguments, this often is the pointee region.
  SVal V = Call.getArgSVal(ArgIdx);
  if (const MemRegion *R = V.getAsRegion())
    return getBaseRegionOrSelf(R);

  // Fall back to expression-based region (for &member expressions).
  if (const MemRegion *R2 = exprToRegion(ArgE, C))
    return getBaseRegionOrSelf(R2);

  // As another fallback, if ArgE is an lvalue pointer variable, resolve via PtrPointsTo.
  if (const MemRegion *VarR = exprToBaseRegion(ArgE, C)) {
    const MemRegion *Resolved = resolvePointerVarToPointee(State, VarR);
    return getBaseRegionOrSelf(Resolved);
  }

  return nullptr;
}

bool SAGenTestChecker::isFalsePositive(const CallEvent &Call, unsigned ArgIdx,
                                       CheckerContext &C, ProgramStateRef State,
                                       const MemRegion *ArgPointee) {
  // 1) The parameter must be a pointer to a work or timer type.
  const Expr *ArgE = Call.getArgExpr(ArgIdx);
  if (!ArgE)
    return true;
  QualType ArgTy = ArgE->getType();
  if (!isWorkOrTimerPointerType(ArgTy))
    return true;

  // 2) The pointee must be provably within a tracked netdev priv region.
  const MemRegion *PrivBase = nullptr;
  const MemRegion *DevBase = findDevForPrivDerivedRegion(State, ArgPointee, &PrivBase);
  if (!DevBase || !PrivBase)
    return true;

  // 3) If the dev isn't known freed, then this isn't our bug.
  if (!devIsFreed(State, DevBase))
    return true;

  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Record dev free when free_netdev(dev) is called.
  if (callHasName(Call, C, "free_netdev")) {
    if (Call.getNumArgs() >= 1) {
      const Expr *DevE = Call.getArgExpr(0);
      const MemRegion *DevBase = exprToBaseRegion(DevE, C);
      if (DevBase) {
        State = State->add<FreedDevs>(DevBase);
        C.addTransition(State);
      }
    }
    return;
  }

  // Learn priv->dev mapping for netdev_priv(dev).
  if (callHasName(Call, C, "netdev_priv")) {
    const Expr *DevE = (Call.getNumArgs() >= 1) ? Call.getArgExpr(0) : nullptr;
    const MemRegion *DevBase = exprToBaseRegion(DevE, C);

    // Try to get the region representing the returned pointer's pointee.
    const SVal RetV = Call.getReturnValue();
    const MemRegion *PrivReg = RetV.getAsRegion(); // Pointee region for pointer returns.

    // Report if netdev_priv(dev) is called after free(dev)
    if (DevBase && devIsFreed(State, DevBase)) {
      reportUAFAtCall(Call, C, "netdev_priv(dev) after free_netdev");
      return;
    }

    // Record mapping priv(pointee) -> dev
    if (PrivReg && DevBase) {
      const MemRegion *PrivBase = getBaseRegionOrSelf(PrivReg);
      State = State->set<Priv2DevMap>(PrivBase, DevBase);
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Detect uses of priv-derived pointers after free_netdev() via known-deref functions.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!knownWorkOrTimerDeref(Call, C, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    // Resolve pointee region of the argument robustly.
    const MemRegion *ArgPointee = getArgPointeeRegion(Call, Idx, C, State);
    if (!ArgPointee)
      continue;

    // Filter out non-work/timer and non-priv cases early.
    if (isFalsePositive(Call, Idx, C, State, ArgPointee))
      continue;

    // If we reached here, it's a proven use of a work/timer inside netdev priv after dev free.
    reportUAFAtCall(Call, C, "Use of netdev priv after free_netdev");
    return;
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Only consider loads that happen as part of arguments to known-deref functions.
  const CallExpr *CE = nullptr;
  unsigned ArgIdx = 0;
  if (!findEnclosingCallArg(S, C, CE, ArgIdx))
    return;

  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!knownWorkOrTimerDerefCE(CE, C, DerefParams))
    return;

  bool Matches = llvm::is_contained(DerefParams, ArgIdx);
  if (!Matches)
    return;

  const Expr *ArgE = CE->getArg(ArgIdx);
  if (!ArgE)
    return;

  // Type-based gating to avoid noise.
  if (!isWorkOrTimerPointerType(ArgE->getType()))
    return;

  ProgramStateRef State = C.getState();

  // Try to resolve the pointee region of the argument.
  SVal ArgSV = C.getState()->getSVal(ArgE, C.getLocationContext());
  const MemRegion *ArgReg = ArgSV.getAsRegion();
  if (!ArgReg)
    ArgReg = exprToRegion(ArgE, C);
  if (!ArgReg)
    return;
  ArgReg = getBaseRegionOrSelf(ArgReg);

  const MemRegion *PrivBase = nullptr;
  const MemRegion *DevBase = findDevForPrivDerivedRegion(State, ArgReg, &PrivBase);
  if (!DevBase || !PrivBase)
    return;

  if (devIsFreed(State, DevBase)) {
    reportUAFAtStmt(CE, C, "Use of netdev priv after free_netdev");
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track pointer variable -> pointee mapping (directed).
  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;

  const auto *TVR = dyn_cast<TypedValueRegion>(LHS);
  if (!TVR || !TVR->getValueType()->isPointerType())
    return;

  const MemRegion *Pointee = Val.getAsRegion();
  if (!Pointee)
    return;

  State = State->set<PtrPointsTo>(LHS, getBaseRegionOrSelf(Pointee));
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of netdev private data after free_netdev (e.g., cancel_work_sync on priv fields)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
