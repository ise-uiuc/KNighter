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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/AST/Decl.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(StructInitRiskMap, const VarDecl *, bool)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::PreCall,
        check::PostCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Kernel infoleak: partial struct init",
                       "Memory Management")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helpers
  static bool isLocalRecordVar(const VarDecl *VD);
  static const VarDecl *getVarDeclFromArg(const Expr *E, CheckerContext &C,
                                          const MemRegion **OutMR = nullptr);
  static bool isZeroInt(const Expr *E, CheckerContext &C);
  static bool isSizeofVar(const Expr *LenExpr, const VarDecl *VD, CheckerContext &C);
  static bool isMemsetCall(const CallEvent &Call, CheckerContext &C);
  static bool isMemsetZeroWholeVar(const CallEvent &Call, const VarDecl *&OutVD,
                                   CheckerContext &C);
  static bool getExportToUserLayout(const CallEvent &Call, unsigned &LenIdx,
                                    unsigned &DataIdx, CheckerContext &C);

  void reportLeak(const Expr *DataE, const Expr *LenE, CheckerContext &C) const;
};

// ----------------- Helper Implementations -----------------

bool SAGenTestChecker::isLocalRecordVar(const VarDecl *VD) {
  if (!VD)
    return false;
  if (!VD->isLocalVarDecl() || !VD->hasLocalStorage())
    return false;
  if (VD->isStaticLocal())
    return false;
  QualType T = VD->getType();
  return T->isRecordType();
}

const VarDecl *SAGenTestChecker::getVarDeclFromArg(const Expr *E, CheckerContext &C,
                                                   const MemRegion **OutMR) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  const MemRegion *Base = MR->getBaseRegion();
  if (!Base)
    return nullptr;

  // We only accept taking the address of the whole object, not subfields/elements.
  if (!isa<VarRegion>(MR))
    return nullptr;

  const auto *VR = dyn_cast<VarRegion>(Base);
  if (!VR)
    return nullptr;
  const auto *VD = dyn_cast<VarDecl>(VR->getDecl());
  if (OutMR)
    *OutMR = MR;
  return VD;
}

bool SAGenTestChecker::isZeroInt(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C)) {
    return Res == 0;
  }
  return false;
}

bool SAGenTestChecker::isSizeofVar(const Expr *LenExpr, const VarDecl *VD, CheckerContext &C) {
  if (!LenExpr || !VD)
    return false;

  const auto *UETT = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(LenExpr);
  if (!UETT)
    return false;

  if (UETT->getKind() != UETT_SizeOf)
    return false;

  if (UETT->isArgumentType()) {
    QualType Ty = UETT->getArgumentType();
    return C.getASTContext().hasSameUnqualifiedType(Ty, VD->getType());
  } else {
    const Expr *Arg = UETT->getArgumentExpr();
    if (!Arg)
      return false;
    Arg = Arg->IgnoreParenCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Arg)) {
      if (const auto *RefVD = dyn_cast<VarDecl>(DRE->getDecl())) {
        return RefVD == VD;
      }
    }
  }
  return false;
}

bool SAGenTestChecker::isMemsetCall(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  if (ExprHasName(Origin, "memset", C))
    return true;
  if (ExprHasName(Origin, "__builtin_memset", C))
    return true;
  return false;
}

bool SAGenTestChecker::isMemsetZeroWholeVar(const CallEvent &Call, const VarDecl *&OutVD,
                                            CheckerContext &C) {
  OutVD = nullptr;
  if (!isMemsetCall(Call, C))
    return false;

  if (Call.getNumArgs() < 3)
    return false;

  // Arg0: destination buffer
  const Expr *BufE = Call.getArgExpr(0);
  const VarDecl *VD = getVarDeclFromArg(BufE, C);
  if (!isLocalRecordVar(VD))
    return false;

  // Arg1: value should be zero
  const Expr *ValE = Call.getArgExpr(1);
  if (!isZeroInt(ValE, C))
    return false;

  // Arg2: size should be sizeof(VD) or sizeof(type-of-VD)
  const Expr *SizeE = Call.getArgExpr(2);
  if (!isSizeofVar(SizeE, VD, C))
    return false;

  OutVD = VD;
  return true;
}

bool SAGenTestChecker::getExportToUserLayout(const CallEvent &Call, unsigned &LenIdx,
                                             unsigned &DataIdx, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // nla_put(skb, type, len, data)
  if (ExprHasName(Origin, "nla_put", C)) {
    if (Call.getNumArgs() >= 4) {
      LenIdx = 2;
      DataIdx = 3;
      return true;
    }
  }

  // nla_put_64bit(skb, type, len, data, padattr)
  if (ExprHasName(Origin, "nla_put_64bit", C)) {
    if (Call.getNumArgs() >= 5) {
      LenIdx = 2;
      DataIdx = 3;
      return true;
    }
  }

  // nla_put_nohdr(skb, len, data)
  if (ExprHasName(Origin, "nla_put_nohdr", C)) {
    if (Call.getNumArgs() >= 3) {
      LenIdx = 0;
      DataIdx = 1;
      return true;
    }
  }

  // copy_to_user(to, from, n)
  if (ExprHasName(Origin, "copy_to_user", C)) {
    if (Call.getNumArgs() >= 3) {
      LenIdx = 2;
      DataIdx = 1;
      return true;
    }
  }

  // copy_to_user_iter(to, from, bytes)
  if (ExprHasName(Origin, "copy_to_user_iter", C)) {
    if (Call.getNumArgs() >= 3) {
      LenIdx = 2;
      DataIdx = 1;
      return true;
    }
  }

  return false;
}

void SAGenTestChecker::reportLeak(const Expr *DataE, const Expr *LenE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Partially initialized stack struct copied to user; zero it with memset.", N);
  if (DataE)
    R->addRange(DataE->getSourceRange());
  if (LenE)
    R->addRange(LenE->getSourceRange());
  C.emitReport(std::move(R));
}

// ----------------- Checker Callbacks -----------------

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (!isLocalRecordVar(VD))
      continue;

    bool Risky = true; // default risky unless proven safe

    if (!VD->hasInit()) {
      // No initializer: risky.
      Risky = true;
    } else {
      const Expr *Init = VD->getInit();
      if (const auto *ILE = dyn_cast<InitListExpr>(Init->IgnoreImplicit())) {
        // {} -> safe; any other partial init -> risky
        if (ILE->getNumInits() == 0)
          Risky = false;
        else
          Risky = true;
      } else {
        // Other forms: conservatively mark risky
        Risky = true;
      }
    }

    const bool *Old = State->get<StructInitRiskMap>(VD);
    if (!Old || *Old != Risky) {
      State = State->set<StructInitRiskMap>(VD, Risky);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Detect memset(&var, 0, sizeof(var or type))
  const VarDecl *VD = nullptr;
  if (isMemsetZeroWholeVar(Call, VD, C) && VD) {
    // Mark as safe
    State = State->set<StructInitRiskMap>(VD, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  unsigned LenIdx = 0, DataIdx = 0;
  if (!getExportToUserLayout(Call, LenIdx, DataIdx, C))
    return;

  if (Call.getNumArgs() <= std::max(LenIdx, DataIdx))
    return;

  const Expr *DataE = Call.getArgExpr(DataIdx);
  const MemRegion *MR = nullptr;
  const VarDecl *VD = getVarDeclFromArg(DataE, C, &MR);
  if (!VD || !isLocalRecordVar(VD))
    return;

  // Ensure the data pointer is the address of the whole object, not a field/element.
  if (!MR || !isa<VarRegion>(MR))
    return;

  const Expr *LenE = Call.getArgExpr(LenIdx);
  if (!isSizeofVar(LenE, VD, C))
    return;

  const bool *Risky = State->get<StructInitRiskMap>(VD);
  if (Risky && *Risky) {
    reportLeak(DataE, LenE, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects copying partially initialized stack structs (with padding) to user space",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
