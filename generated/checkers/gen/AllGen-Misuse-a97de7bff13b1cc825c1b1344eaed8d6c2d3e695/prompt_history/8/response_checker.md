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
#include "clang/Lex/Lexer.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states required.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe setsockopt copy", "API Misuse")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      bool isCopyFromSockptrFamily(const CallEvent &Call, CheckerContext &C,
                                   unsigned &LenIdx) const;

      bool inSetsockoptFunctionWithParams(const CheckerContext &C,
                                          const FunctionDecl *&FD,
                                          const VarDecl *&OptlenVD,
                                          const VarDecl *&OptvalVD) const;

      void report(CheckerContext &C, const Stmt *S, StringRef Msg) const;
};

bool SAGenTestChecker::isCopyFromSockptrFamily(const CallEvent &Call, CheckerContext &C,
                                               unsigned &LenIdx) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Exclude the correct helper.
  if (ExprHasName(OE, "bt_copy_from_sockptr", C))
    return false;

  // copy_from_sockptr_offset(dst, optval, offset, len)
  if (ExprHasName(OE, "copy_from_sockptr_offset", C)) {
    if (Call.getNumArgs() < 4)
      return false;
    LenIdx = 3;
    return true;
  }

  // copy_from_sockptr(dst, optval, len)
  if (ExprHasName(OE, "copy_from_sockptr", C)) {
    if (Call.getNumArgs() < 3)
      return false;
    LenIdx = 2;
    return true;
  }

  return false;
}

bool SAGenTestChecker::inSetsockoptFunctionWithParams(const CheckerContext &C,
                                                      const FunctionDecl *&FD,
                                                      const VarDecl *&OptlenVD,
                                                      const VarDecl *&OptvalVD) const {
  OptlenVD = nullptr;
  OptvalVD = nullptr;
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return false;

  const Decl *D = LCtx->getDecl();
  FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;

  std::string Name = FD->getNameAsString();
  if (Name.find("setsockopt") == std::string::npos)
    return false;

  for (const ParmVarDecl *P : FD->parameters()) {
    if (!P)
      continue;
    StringRef PName = P->getName();
    if (PName == "optlen") {
      OptlenVD = P;
    } else if (PName == "optval") {
      OptvalVD = P;
    }
  }

  if (!OptlenVD || !OptvalVD)
    return false;

  // Optionally ensure optlen is an integer type.
  if (!OptlenVD->getType()->isIntegerType())
    return false;

  return true;
}

void SAGenTestChecker::report(CheckerContext &C, const Stmt *S, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned LenIdx = 0;
  if (!isCopyFromSockptrFamily(Call, C, LenIdx))
    return;

  const FunctionDecl *FD = nullptr;
  const VarDecl *OptlenVD = nullptr;
  const VarDecl *OptvalVD = nullptr;
  if (!inSetsockoptFunctionWithParams(C, FD, OptlenVD, OptvalVD))
    return;

  // Get the length expression.
  if (LenIdx >= Call.getNumArgs())
    return;

  const Expr *LenE = Call.getArgExpr(LenIdx);
  if (!LenE)
    return;

  // Partial-copy pattern: passing optlen directly or via expression mentioning it.
  if (ExprHasName(LenE, "optlen", C)) {
    report(C, LenE, "setsockopt copies partial user buffer; reject short optlen");
    return;
  }

  // Try to resolve length to a constant K (e.g., sizeof(u32), sizeof(*dst)).
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, LenE, C)) {
    // Not a known constant length; keep conservative and do not report.
    return;
  }

  ProgramStateRef State = C.getState();
  if (!State)
    return;

  // Fetch the symbolic value of 'optlen'.
  MemRegionManager &MRMgr = State->getRegionManager();
  const MemRegion *OptlenRegion = MRMgr.getVarRegion(OptlenVD, C.getLocationContext());
  if (!OptlenRegion)
    return;

  SVal OptlenVal = State->getSVal(loc::MemRegionVal(OptlenRegion));
  if (OptlenVal.isUnknownOrUndef())
    return;

  SValBuilder &SB = C.getSValBuilder();

  // Create constant K SVal.
  SVal KVal = SB.makeIntVal(EvalRes);

  // Build comparison: optlen >= K
  SVal Cond = SB.evalBinOp(State, BO_GE, OptlenVal, KVal, C.getASTContext().IntTy);
  if (Cond.isUnknownOrUndef())
    return;

  DefinedOrUnknownSVal D = Cond.castAs<DefinedOrUnknownSVal>();
  ProgramStateRef StateTrue = State->assume(D, true);
  ProgramStateRef StateFalse = State->assume(D, false);

  // If not definitely true (i.e., StateFalse exists), report.
  if (StateFalse) {
    report(C, LenE, "copy_from_sockptr without validating optlen");
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe copy_from_sockptr in setsockopt without validating optlen, or partial-copy patterns",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
