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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <algorithm>
#include <cstdint>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps:
// - ZeroedStructMap: base region of a local struct -> true if definitely fully zeroed to sizeof(struct)
// - PtrAliasMap: pointer region -> base pointee region (e.g., p -> VarRegion(s))
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedStructMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PreCall,
                                        check::PostCall,
                                        check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Copying non-zeroed stack struct to user", "Kernel Information Leak")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static bool isMemsetLike(const CallEvent &Call, CheckerContext &C);
      static bool isMemzeroLike(const CallEvent &Call, CheckerContext &C);

      static bool isUserCopySink(const CallEvent &Call, CheckerContext &C,
                                 unsigned &LenIdx, unsigned &DataIdx);

      static const MemRegion *extractPointeeBaseRegion(const Expr *PtrExpr,
                                                       CheckerContext &C);

      static bool isLocalStructVarRegion(const MemRegion *R);
      static uint64_t getTypeSizeInBytes(QualType QT, ASTContext &Ctx);

      static bool evalSizeArgEqualsVarSize(const Expr *LenE,
                                           const VarRegion *VR,
                                           CheckerContext &C);

      static bool evalExprIsZero(const Expr *E, CheckerContext &C);

      void markZeroedIfFullSize(const Expr *DstE,
                                const Expr *LenE,
                                bool ImplicitZero,
                                const Expr *ValE,
                                CheckerContext &C) const;

      void reportLeakAtCall(const CallEvent &Call, CheckerContext &C) const;
};

// Determine if the call is memset-like (memset/__memset/__builtin_memset).
bool SAGenTestChecker::isMemsetLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "memset", C) ||
         ExprHasName(Origin, "__memset", C) ||
         ExprHasName(Origin, "__builtin_memset", C);
}

// Determine if the call is memzero-like (memzero_explicit/bzero).
bool SAGenTestChecker::isMemzeroLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "memzero_explicit", C) ||
         ExprHasName(Origin, "bzero", C);
}

// Identify sinks that copy data to user or netlink attribute with explicit length and data pointer.
// Returns true and sets LenIdx/DataIdx if recognized.
bool SAGenTestChecker::isUserCopySink(const CallEvent &Call, CheckerContext &C,
                                      unsigned &LenIdx, unsigned &DataIdx) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Order matters because ExprHasName checks for substring containment.
  if (ExprHasName(Origin, "nla_put_64bit", C)) {
    if (Call.getNumArgs() >= 4) {
      LenIdx = 2; DataIdx = 3; return true;
    }
  }
  if (ExprHasName(Origin, "nla_put", C)) {
    if (Call.getNumArgs() >= 4) {
      LenIdx = 2; DataIdx = 3; return true;
    }
  }
  if (ExprHasName(Origin, "__copy_to_user", C)) {
    if (Call.getNumArgs() >= 3) {
      LenIdx = 2; DataIdx = 1; return true;
    }
  }
  if (ExprHasName(Origin, "copy_to_user_iter", C)) {
    if (Call.getNumArgs() >= 3) {
      LenIdx = 2; DataIdx = 1; return true;
    }
  }
  if (ExprHasName(Origin, "copy_to_user", C)) {
    if (Call.getNumArgs() >= 3) {
      LenIdx = 2; DataIdx = 1; return true;
    }
  }
  if (ExprHasName(Origin, "_copy_to_iter", C)) {
    if (Call.getNumArgs() >= 2) {
      LenIdx = 1; DataIdx = 0; return true;
    }
  }
  return false;
}

// Follow alias map to get the ultimate base region (ideally a VarRegion of the struct).
const MemRegion *SAGenTestChecker::extractPointeeBaseRegion(const Expr *PtrExpr,
                                                            CheckerContext &C) {
  if (!PtrExpr)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(PtrExpr, C);
  if (!MR)
    return nullptr;

  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;

  ProgramStateRef State = C.getState();
  // Follow alias chain: pointer region -> base pointee region.
  const MemRegion *Cur = MR;
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (true) {
    if (!Cur)
      break;
    if (!Visited.insert(Cur).second)
      break; // avoid cycles
    const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Cur);
    if (!NextPtr)
      break;
    const MemRegion *Next = *NextPtr;
    if (!Next)
      break;
    Cur = Next->getBaseRegion();
  }
  return Cur ? Cur->getBaseRegion() : nullptr;
}

bool SAGenTestChecker::isLocalStructVarRegion(const MemRegion *R) {
  if (!R)
    return false;
  const VarRegion *VR = dyn_cast<VarRegion>(R);
  if (!VR)
    return false;
  const VarDecl *VD = dyn_cast<VarDecl>(VR->getDecl());
  if (!VD)
    return false;
  if (!VD->hasLocalStorage() || !VD->isLocalVarDecl())
    return false;
  QualType T = VD->getType();
  return !T.isNull() && T->isRecordType();
}

uint64_t SAGenTestChecker::getTypeSizeInBytes(QualType QT, ASTContext &Ctx) {
  if (QT.isNull())
    return 0;
  return Ctx.getTypeSizeInChars(QT).getQuantity();
}

bool SAGenTestChecker::evalSizeArgEqualsVarSize(const Expr *LenE,
                                                const VarRegion *VR,
                                                CheckerContext &C) {
  if (!LenE || !VR)
    return false;
  llvm::APSInt Res;
  if (!EvaluateExprToInt(Res, LenE, C))
    return false;

  const VarDecl *VD = dyn_cast<VarDecl>(VR->getDecl());
  if (!VD)
    return false;
  uint64_t VarSize = getTypeSizeInBytes(VD->getType(), C.getASTContext());

  // Compare as unsigned
  uint64_t LenVal = Res.isSigned() ? Res.getSExtValue() : Res.getZExtValue();
  return LenVal == VarSize;
}

bool SAGenTestChecker::evalExprIsZero(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt Res;
  if (!EvaluateExprToInt(Res, E, C))
    return false;
  return Res == 0;
}

// If destination points to a local struct, and the length equals sizeof(struct),
// and the value is zero (or implicit zero), mark the struct as zeroed.
void SAGenTestChecker::markZeroedIfFullSize(const Expr *DstE,
                                            const Expr *LenE,
                                            bool ImplicitZero,
                                            const Expr *ValE,
                                            CheckerContext &C) const {
  if (!DstE || !LenE)
    return;

  if (!ImplicitZero) {
    if (!ValE)
      return;
    if (!evalExprIsZero(ValE, C))
      return;
  }

  const MemRegion *Base = extractPointeeBaseRegion(DstE, C);
  if (!Base)
    return;
  const VarRegion *VR = dyn_cast<VarRegion>(Base);
  if (!VR)
    return;

  if (!isLocalStructVarRegion(VR))
    return;

  if (!evalSizeArgEqualsVarSize(LenE, VR, C))
    return;

  ProgramStateRef State = C.getState();
  State = State->set<ZeroedStructMap>(VR, true);
  C.addTransition(State);
}

// Track pointer aliasing: if LHS is a pointer var and RHS is &struct or another pointer alias,
// map LHS region -> ultimate base pointee region.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }

  const MemRegion *RReg = Val.getAsRegion();
  if (!RReg) {
    // We could drop the alias, but keep it simple: do nothing.
    C.addTransition(State);
    return;
  }
  RReg = RReg->getBaseRegion();
  if (!RReg) {
    C.addTransition(State);
    return;
  }

  // Resolve RHS to ultimate base if it's already an alias.
  const MemRegion *Ultimate = RReg;
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (true) {
    if (!Ultimate)
      break;
    if (!Visited.insert(Ultimate).second)
      break;
    const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Ultimate);
    if (!NextPtr)
      break;
    const MemRegion *Next = *NextPtr;
    if (!Next)
      break;
    Ultimate = Next->getBaseRegion();
  }

  State = State->set<PtrAliasMap>(LHSReg, Ultimate);
  C.addTransition(State);
}

// Post-call: detect zeroing operations and mark structs as fully zeroed.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (isMemsetLike(Call, C)) {
    if (Call.getNumArgs() >= 3) {
      const Expr *DstE = Call.getArgExpr(0);
      const Expr *ValE = Call.getArgExpr(1);
      const Expr *LenE = Call.getArgExpr(2);
      markZeroedIfFullSize(DstE, LenE, false, ValE, C);
    }
    return;
  }

  if (isMemzeroLike(Call, C)) {
    if (Call.getNumArgs() >= 2) {
      const Expr *DstE = Call.getArgExpr(0);
      const Expr *LenE = Call.getArgExpr(1);
      markZeroedIfFullSize(DstE, LenE, true, nullptr, C);
    }
    return;
  }
}

// Pre-call: report if copying a local stack struct by sizeof(struct) without prior zeroing.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned LenIdx = 0, DataIdx = 0;
  if (!isUserCopySink(Call, C, LenIdx, DataIdx))
    return;

  if (Call.getNumArgs() <= std::max(LenIdx, DataIdx))
    return;

  const Expr *DataE = Call.getArgExpr(DataIdx);
  const Expr *LenE = Call.getArgExpr(LenIdx);
  if (!DataE || !LenE)
    return;

  const MemRegion *Base = extractPointeeBaseRegion(DataE, C);
  if (!Base)
    return;

  const VarRegion *VR = dyn_cast<VarRegion>(Base);
  if (!VR)
    return;

  if (!isLocalStructVarRegion(VR))
    return;

  if (!evalSizeArgEqualsVarSize(LenE, VR, C))
    return;

  ProgramStateRef State = C.getState();
  const bool *Zeroed = State->get<ZeroedStructMap>(VR);
  // If not marked as zeroed, warn.
  if (!(Zeroed && *Zeroed)) {
    reportLeakAtCall(Call, C);
  }
}

void SAGenTestChecker::reportLeakAtCall(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Copying non-zeroed stack struct to user; zero it first.", N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects copying of partially-initialized stack structs to user space without zeroing",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
