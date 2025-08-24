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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include <cstdint>

using namespace clang;
using namespace ento;
using namespace taint;

// Map: per-function optlen parameter -> greatest known lower bound on current path
REGISTER_MAP_WITH_PROGRAMSTATE(OptlenLBMap, const ParmVarDecl*, uint64_t)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PreCall,
        check::BranchCondition
      > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe copy_from_sockptr in setsockopt", "Security")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helper utilities per plan
      static bool isSetSockoptHandler(const FunctionDecl *FD);
      static const ParmVarDecl *findOptlenParam(const FunctionDecl *FD);
      static bool isCopyFromSockptrLike(const CallEvent &Call, CheckerContext &C, unsigned &SizeArgIndex);
      static bool getConstSizeFromExpr(const Expr *E, CheckerContext &C, uint64_t &Out);

      static bool extractOptlenCompare(const Stmt *Cond,
                                       const ParmVarDecl *OptlenPVD,
                                       const Expr *&SizeExpr,
                                       BinaryOperatorKind &Op,
                                       bool &OptlenOnLHS);

      static ProgramStateRef setLBMax(ProgramStateRef State,
                                      const ParmVarDecl *PVD,
                                      uint64_t NewLB);

      void reportUnsafeCopy(const CallEvent &Call, const Expr *SizeArg, CheckerContext &C) const;
};

// ---- Helper implementations ----

bool SAGenTestChecker::isSetSockoptHandler(const FunctionDecl *FD) {
  if (!FD)
    return false;
  StringRef Name = FD->getName();
  if (!Name.contains("setsockopt"))
    return false;

  const ParmVarDecl *Optlen = nullptr;
  const ParmVarDecl *Optval = nullptr;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (!P || !P->getIdentifier()) continue;
    StringRef PName = P->getName();
    if (PName == "optlen")
      Optlen = P;
    else if (PName == "optval")
      Optval = P;
  }
  if (!Optlen || !Optval)
    return false;

  // Basic integer type check for optlen
  QualType QT = Optlen->getType();
  if (!QT->isIntegerType())
    return false;

  return true;
}

const ParmVarDecl *SAGenTestChecker::findOptlenParam(const FunctionDecl *FD) {
  if (!FD) return nullptr;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (!P || !P->getIdentifier()) continue;
    if (P->getName() == "optlen" && P->getType()->isIntegerType())
      return P;
  }
  return nullptr;
}

bool SAGenTestChecker::isCopyFromSockptrLike(const CallEvent &Call, CheckerContext &C, unsigned &SizeArgIndex) {
  SizeArgIndex = 0;
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Ignore the safe helper
  if (ExprHasName(Origin, "bt_copy_from_sockptr", C))
    return false;

  // Match the unsafe helpers
  if (ExprHasName(Origin, "copy_from_sockptr_offset", C)) {
    // Per plan: size index = 3 (0-based). Some kernels have size at index 2,
    // but we follow the plan and guard with bounds below.
    if (Call.getNumArgs() > 3) {
      SizeArgIndex = 3;
    } else if (Call.getNumArgs() > 2) {
      // Fallback for alternate signature (size at index 2)
      SizeArgIndex = 2;
    } else {
      return false;
    }
    return true;
  }
  if (ExprHasName(Origin, "copy_from_sockptr", C)) {
    if (Call.getNumArgs() > 2) {
      SizeArgIndex = 2;
      return true;
    }
  }

  return false;
}

bool SAGenTestChecker::getConstSizeFromExpr(const Expr *E, CheckerContext &C, uint64_t &Out) {
  if (!E)
    return false;
  llvm::APSInt Val;
  if (!EvaluateExprToInt(Val, E, C))
    return false;
  Out = Val.getZExtValue();
  return true;
}

bool SAGenTestChecker::extractOptlenCompare(const Stmt *Cond,
                                            const ParmVarDecl *OptlenPVD,
                                            const Expr *&SizeExpr,
                                            BinaryOperatorKind &Op,
                                            bool &OptlenOnLHS) {
  SizeExpr = nullptr;
  OptlenOnLHS = false;

  const Expr *E = dyn_cast_or_null<Expr>(Cond);
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO)
    return false;

  BinaryOperatorKind Opc = BO->getOpcode();
  switch (Opc) {
    case BO_LT:
    case BO_LE:
    case BO_GT:
    case BO_GE:
    case BO_EQ:
    case BO_NE:
      break;
    default:
      return false;
  }

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  auto IsOptlenRef = [&](const Expr *X) -> bool {
    const auto *DRE = dyn_cast<DeclRefExpr>(X);
    if (!DRE) return false;
    const auto *VD = dyn_cast<ParmVarDecl>(DRE->getDecl());
    if (!VD) return false;
    return VD == OptlenPVD;
  };

  if (IsOptlenRef(LHS)) {
    // optlen <something>
    OptlenOnLHS = true;
    SizeExpr = RHS;
    Op = Opc;
    return true;
  }
  if (IsOptlenRef(RHS)) {
    // <something> opt optlen
    OptlenOnLHS = false;
    SizeExpr = LHS;
    Op = Opc;
    return true;
  }

  return false;
}

ProgramStateRef SAGenTestChecker::setLBMax(ProgramStateRef State,
                                           const ParmVarDecl *PVD,
                                           uint64_t NewLB) {
  if (!State || !PVD)
    return State;
  const uint64_t *Old = State->get<OptlenLBMap>(PVD);
  if (!Old || *Old < NewLB)
    State = State->set<OptlenLBMap>(PVD, NewLB);
  return State;
}

// ---- Main logic ----

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!isSetSockoptHandler(FD))
    return;

  const ParmVarDecl *OptlenPVD = findOptlenParam(FD);
  if (!OptlenPVD)
    return;

  const Expr *SizeExpr = nullptr;
  BinaryOperatorKind Op;
  bool OptlenOnLHS = false;

  if (!extractOptlenCompare(Condition, OptlenPVD, SizeExpr, Op, OptlenOnLHS))
    return;

  uint64_t S = 0;
  if (!getConstSizeFromExpr(SizeExpr, C, S))
    return;

  // If optlen is on RHS, flip operator to canonical form "optlen ? S"
  auto FlipOpForRHS = [](BinaryOperatorKind O) {
    switch (O) {
      case BO_LT: return BO_GT;   // S < optlen  -> optlen > S
      case BO_LE: return BO_GE;   // S <= optlen -> optlen >= S
      case BO_GT: return BO_LT;   // S > optlen  -> optlen < S
      case BO_GE: return BO_LE;   // S >= optlen -> optlen <= S
      case BO_EQ: return BO_EQ;
      case BO_NE: return BO_NE;
      default:    return O;
    }
  };

  BinaryOperatorKind CanonOp = Op;
  if (!OptlenOnLHS)
    CanonOp = FlipOpForRHS(Op);

  // Determine bounds for true/false branches
  bool HasTrue = false, HasFalse = false;
  uint64_t LBTrue = 0, LBFalse = 0;

  switch (CanonOp) {
    case BO_GE:
      // optlen >= S : true -> LB >= S
      HasTrue = true; LBTrue = S;
      break;
    case BO_GT:
      // optlen > S : true -> LB >= S+1
      HasTrue = true; LBTrue = S + 1;
      break;
    case BO_LT:
      // optlen < S : false -> optlen >= S
      HasFalse = true; LBFalse = S;
      break;
    case BO_LE:
      // optlen <= S : false -> optlen >= S+1
      HasFalse = true; LBFalse = S + 1;
      break;
    case BO_EQ:
      // optlen == S : true -> LB >= S
      HasTrue = true; LBTrue = S;
      break;
    case BO_NE:
      // optlen != S : no guaranteed LB
      break;
    default:
      break;
  }

  if (!HasTrue && !HasFalse)
    return;

  ProgramStateRef State = C.getState();
  ProgramStateRef StateT = State, StateF = State;

  if (HasTrue)
    StateT = setLBMax(StateT, OptlenPVD, LBTrue);
  if (HasFalse)
    StateF = setLBMax(StateF, OptlenPVD, LBFalse);

  if (HasTrue)
    C.addTransition(StateT);
  if (HasFalse)
    C.addTransition(StateF);
}

void SAGenTestChecker::reportUnsafeCopy(const CallEvent &Call, const Expr *SizeArg, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_from_sockptr uses fixed size without validating optlen", N);

  if (SizeArg)
    R->addRange(SizeArg->getSourceRange());

  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned SizeIdx = 0;
  if (!isCopyFromSockptrLike(Call, C, SizeIdx))
    return;

  const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!isSetSockoptHandler(FD))
    return;

  const ParmVarDecl *OptlenPVD = findOptlenParam(FD);
  if (!OptlenPVD)
    return;

  if (SizeIdx >= Call.getNumArgs())
    return;

  const Expr *SizeArg = Call.getArgExpr(SizeIdx);
  if (!SizeArg)
    return;

  uint64_t CopySize = 0;
  if (!getConstSizeFromExpr(SizeArg, C, CopySize))
    return; // Do not warn if size is not a constant we can evaluate.

  ProgramStateRef State = C.getState();
  uint64_t LB = 0;
  if (const uint64_t *KnownLB = State->get<OptlenLBMap>(OptlenPVD))
    LB = *KnownLB;

  if (LB >= CopySize)
    return; // validated on this path

  // No sufficient prior validation
  reportUnsafeCopy(Call, SizeArg, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe fixed-size copy_from_sockptr in setsockopt without validating optlen",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
