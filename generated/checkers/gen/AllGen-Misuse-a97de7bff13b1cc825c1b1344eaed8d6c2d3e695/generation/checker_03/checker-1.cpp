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
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Missing optlen validation in setsockopt", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Returns true if Call is a target "copy_from_sockptr"-like function that does NOT
      // enforce/validate optlen itself. If true, fills in indices for size and sockptr args.
      bool isCopyFromSockptrLike(const CallEvent &Call, CheckerContext &C,
                                 unsigned &SizeArgIdx, unsigned &SockptrArgIdx) const;

      // Heuristically identify setsockopt-like handlers and optionally locate the sockptr and optlen params.
      bool inSetsockoptContext(const FunctionDecl *FD,
                               const ParmVarDecl *&SockptrParam,
                               const ParmVarDecl *&OptlenParam) const;

      void report(const CallEvent &Call, CheckerContext &C) const;
};

bool SAGenTestChecker::isCopyFromSockptrLike(const CallEvent &Call, CheckerContext &C,
                                             unsigned &SizeArgIdx, unsigned &SockptrArgIdx) const {
  SizeArgIdx = SockptrArgIdx = (unsigned)-1;

  const Expr *Origin = Call.getOriginExpr();
  // Skip helper that enforces optlen
  if (Origin && ExprHasName(Origin, "bt_copy_from_sockptr", C))
    return false;

  // Positive matches by origin expr text
  if (Origin && ExprHasName(Origin, "copy_from_sockptr_offset", C)) {
    SockptrArgIdx = 1;
    SizeArgIdx = 3;
    return true;
  }
  if (Origin && ExprHasName(Origin, "copy_from_sockptr", C)) {
    SockptrArgIdx = 1;
    SizeArgIdx = 2;
    return true;
  }

  // Fallback to callee identifier (in case macro/text is transformed)
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Name = ID->getName();
    if (Name == "bt_copy_from_sockptr")
      return false;
    if (Name == "copy_from_sockptr_offset") {
      SockptrArgIdx = 1;
      SizeArgIdx = 3;
      return true;
    }
    if (Name == "copy_from_sockptr") {
      SockptrArgIdx = 1;
      SizeArgIdx = 2;
      return true;
    }
  }

  return false;
}

bool SAGenTestChecker::inSetsockoptContext(const FunctionDecl *FD,
                                           const ParmVarDecl *&SockptrParam,
                                           const ParmVarDecl *&OptlenParam) const {
  SockptrParam = nullptr;
  OptlenParam = nullptr;
  if (!FD)
    return false;

  // Name-based heuristic
  std::string FnName = FD->getNameAsString();
  std::string Lower = llvm::StringRef(FnName).lower();
  bool NameSuggests = (Lower.find("setsockopt") != std::string::npos);

  // Parameter-based heuristic: find sockptr_t param and optlen integer param named "optlen".
  for (const ParmVarDecl *P : FD->parameters()) {
    QualType PT = P->getType();
    std::string TyStr = PT.getAsString();
    if (!SockptrParam && TyStr.find("sockptr_t") != std::string::npos) {
      SockptrParam = P;
    }
    if (!OptlenParam && P->getName() == "optlen" && PT->isIntegerType()) {
      OptlenParam = P;
    }
  }

  bool ParamSuggests = (SockptrParam != nullptr && OptlenParam != nullptr);
  return NameSuggests || ParamSuggests;
}

void SAGenTestChecker::report(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "copy_from_sockptr uses fixed size without validating optlen",
      N);
  if (const Stmt *S = Call.getOriginExpr())
    R->addRange(S->getSourceRange());

  const SourceManager &SM = C.getSourceManager();
  const LocationContext *LC = C.getLocationContext();
  const Stmt *SLoc = Call.getOriginExpr();
  PathDiagnosticLocation PDL = SLoc ? PathDiagnosticLocation::createBegin(SLoc, SM, LC)
                                    : PathDiagnosticLocation::createBegin(LC->getDecl(), SM);

  R->addNote("Use bt_copy_from_sockptr(..., sizeof(obj), optval, optlen) or validate optlen == sizeof(obj).",
             PDL);
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned SizeIdx = 0, SockptrIdx = 0;
  if (!isCopyFromSockptrLike(Call, C, SizeIdx, SockptrIdx))
    return;

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  const ParmVarDecl *SockptrParam = nullptr;
  const ParmVarDecl *OptlenParam = nullptr;
  if (!inSetsockoptContext(FD, SockptrParam, OptlenParam))
    return;

  // Argument bounds
  if (SizeIdx >= Call.getNumArgs() || SockptrIdx >= Call.getNumArgs())
    return;

  const Expr *SizeE = Call.getArgExpr(SizeIdx);
  const Expr *SockptrE = Call.getArgExpr(SockptrIdx);
  if (!SizeE || !SockptrE)
    return;

  // Ensure the source sockptr corresponds to the API's sockptr parameter when we can identify it.
  if (SockptrParam) {
    if (!ExprHasName(SockptrE, SockptrParam->getName(), C))
      return;
  }

  // If size mentions optlen directly, consider validated and skip.
  if (OptlenParam) {
    if (ExprHasName(SizeE, OptlenParam->getName(), C))
      return;
  }

  // Check for fixed-size usage (constant or sizeof in the size expression).
  llvm::APSInt Dummy;
  bool IsConst = EvaluateExprToInt(Dummy, SizeE, C);
  bool MentionsSizeof = ExprHasName(SizeE, "sizeof", C);

  if (!IsConst && !MentionsSizeof)
    return;

  // All checks indicate a likely missing optlen validation.
  report(Call, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect fixed-size copy_from_sockptr in setsockopt without validating optlen",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
