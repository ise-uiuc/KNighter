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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track variables that were computed via min(..., optlen)
REGISTER_SET_WITH_PROGRAMSTATE(MinLenVars, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe copy_from_sockptr in setsockopt", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:
      // Helpers
      static bool isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C);
      static bool isSetsockoptLike(const FunctionDecl *FD);
      static bool isFixedSizeExpr(const Expr *E, CheckerContext &C);
      static bool mentionsOptlen(const Expr *E, CheckerContext &C);
      static bool mentionsMinWithOptlen(const Expr *E, CheckerContext &C);
      static unsigned getSizeArgIndex(const CallEvent &Call, CheckerContext &C, bool &IsSockptrCopy) ;
      void reportAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;
};

bool SAGenTestChecker::isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

bool SAGenTestChecker::isSetsockoptLike(const FunctionDecl *FD) {
  if (!FD)
    return false;

  // Heuristic 1: function name contains "setsockopt"
  if (FD->getNameAsString().find("setsockopt") != std::string::npos)
    return true;

  // Heuristic 2: has sockptr_t-like parameter and an "optlen"-like parameter
  bool HasSockptr = false;
  bool HasOptlen  = false;

  for (const ParmVarDecl *P : FD->parameters()) {
    if (!P)
      continue;

    // Check for sockptr_t by type name or parameter name "optval"
    QualType PTy = P->getType();
    std::string TyStr = PTy.getAsString();
    std::string ParamName = P->getNameAsString();
    if (TyStr.find("sockptr_t") != std::string::npos || ParamName.find("optval") != std::string::npos)
      HasSockptr = true;

    // Check for optlen: name contains "optlen" and integral type
    if (ParamName.find("optlen") != std::string::npos) {
      if (PTy->isIntegerType() || PTy->isUnsignedIntegerType())
        HasOptlen = true;
    }
  }

  return HasSockptr && HasOptlen;
}

bool SAGenTestChecker::mentionsOptlen(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "optlen", C);
}

bool SAGenTestChecker::mentionsMinWithOptlen(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  bool HasMin = ExprHasName(E, "min", C) || ExprHasName(E, "min_t", C);
  if (!HasMin)
    return false;
  return ExprHasName(E, "optlen", C);
}

bool SAGenTestChecker::isFixedSizeExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  // If it mentions optlen, it's not fixed size in our sense.
  if (mentionsOptlen(E, C))
    return false;

  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C)) {
    if (Res.isSigned())
      return Res.isStrictlyPositive();
    return Res != 0;
  }

  // sizeof(...)
  if (isa<UnaryExprOrTypeTraitExpr>(E))
    return true;

  return false;
}

unsigned SAGenTestChecker::getSizeArgIndex(const CallEvent &Call, CheckerContext &C, bool &IsSockptrCopy) {
  IsSockptrCopy = false;
  if (isCallNamed(Call, "copy_from_sockptr_offset", C)) {
    IsSockptrCopy = true;
    // copy_from_sockptr_offset(dst, src, offset, size)
    if (Call.getNumArgs() >= 4)
      return 3;
  } else if (isCallNamed(Call, "copy_from_sockptr", C)) {
    IsSockptrCopy = true;
    // copy_from_sockptr(dst, src, size)
    if (Call.getNumArgs() >= 3)
      return 2;
  }
  // Not a target call or insufficient args
  return UINT_MAX;
}

void SAGenTestChecker::reportAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Ignore safe helper
  if (isCallNamed(Call, "bt_copy_from_sockptr", C))
    return;

  bool IsSockptrCopy = false;
  unsigned SzIdx = getSizeArgIndex(Call, C, IsSockptrCopy);
  if (!IsSockptrCopy || SzIdx == UINT_MAX)
    return;

  // Ensure we are in a setsockopt-like handler to reduce noise
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return;
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (!isSetsockoptLike(FD))
    return;

  // Get size argument and destination argument
  if (SzIdx >= Call.getNumArgs())
    return;

  const Expr *SzArg = Call.getArgExpr(SzIdx);
  if (!SzArg)
    return;

  ProgramStateRef State = C.getState();

  // A) Detect partial copy using min(optlen, ...)
  if (mentionsMinWithOptlen(SzArg, C)) {
    reportAtCall(Call, C, "Partial copy from optval via min(optlen, ...); uninitialized fields possible");
    return;
  } else {
    // If size arg is a local variable that we tracked as min(optlen, ...)
    SVal SzVal = Call.getArgSVal(SzIdx);
    if (const MemRegion *MR = SzVal.getAsRegion()) {
      MR = MR->getBaseRegion();
      if (MR) {
        if (State->contains<MinLenVars>(MR)) {
          reportAtCall(Call, C, "Partial copy from optval via min(optlen, ...); uninitialized fields possible");
          return;
        }
      }
    }
  }

  // B) Detect fixed-size copy without referencing optlen
  if (isFixedSizeExpr(SzArg, C)) {
    // If they explicitly used optlen (already checked), we would have returned.
    // Here, no optlen in size => warn to use bt_copy_from_sockptr.
    reportAtCall(Call, C, "copy_from_sockptr lacks optlen >= size check; use bt_copy_from_sockptr");
    return;
  }

  // Otherwise, do nothing.
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
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

  const Expr *RHSLike = dyn_cast_or_null<Expr>(StoreE);
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(StoreE)) {
    if (BO->getOpcode() == BO_Assign)
      RHSLike = BO->getRHS();
  }

  bool Mark = false;
  if (RHSLike) {
    // If RHS contains min/min_t and also optlen, mark this variable.
    if (mentionsMinWithOptlen(RHSLike, C))
      Mark = true;
  }

  if (Mark) {
    State = State->add<MinLenVars>(LHSReg);
  } else {
    // If not a min/optlen assignment, clear old mark if present to avoid stale info.
    if (State->contains<MinLenVars>(LHSReg))
      State = State->remove<MinLenVars>(LHSReg);
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe copy_from_sockptr usage in setsockopt handlers (missing optlen validation or partial copy via min)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
