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
#include "clang/Lex/Lexer.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe setsockopt copy", "API Misuse")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helper predicates
      static bool isCopyFromSockptrLike(const CallEvent &Call, unsigned &SrcIndex, unsigned &LenIndex, CheckerContext &C);
      static bool isSetsockoptLikeFunction(const FunctionDecl *FD, const ParmVarDecl* &OptValParm, const ParmVarDecl* &OptLenParm);
      static bool exprMentionsOptlenOrMin(const Expr *E, StringRef OptLenName, CheckerContext &C);
      static bool tryGetDeclRefAndInit(const Expr *E, const VarDecl* &VD, const Expr* &Init);

      static bool isIntegerType(QualType QT) {
        return QT->isIntegerType();
      }

      // Recognize if 'LenArg' is derived from a previous assignment like: len = min(..., optlen)
      static bool isLenAssignedFromMinBeforeCall(const VarDecl *LenVar, const Stmt *CallS,
                                                 StringRef OptLenName, CheckerContext &C);

      // Reporting helpers
      void reportFixedSizeNoOptlen(const CallEvent &Call, CheckerContext &C) const;
      void reportPartialCopyMin(const CallEvent &Call, CheckerContext &C) const;
};

bool SAGenTestChecker::isCopyFromSockptrLike(const CallEvent &Call, unsigned &SrcIndex,
                                             unsigned &LenIndex, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Prefer matching by source text using ExprHasName for robustness with macros.
  if (ExprHasName(Origin, "copy_from_sockptr_offset", C)) {
    SrcIndex = 1; // (dst, src, off, len)
    LenIndex = 3;
    return true;
  }
  if (ExprHasName(Origin, "copy_from_sockptr", C)) {
    SrcIndex = 1; // (dst, src, len)
    LenIndex = 2;
    return true;
  }

  // Also fallback on callee identifier if available.
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef N = ID->getName();
    if (N.equals("copy_from_sockptr_offset")) {
      SrcIndex = 1; LenIndex = 3; return true;
    }
    if (N.equals("copy_from_sockptr")) {
      SrcIndex = 1; LenIndex = 2; return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isSetsockoptLikeFunction(const FunctionDecl *FD,
                                                const ParmVarDecl* &OptValParm,
                                                const ParmVarDecl* &OptLenParm) {
  OptValParm = nullptr;
  OptLenParm = nullptr;
  if (!FD)
    return false;

  std::string Name = FD->getNameAsString();
  bool NameHeuristic = (Name.find("setsockopt") != std::string::npos);

  // Search parameters for candidates
  const ParmVarDecl *OptValCand = nullptr;
  const ParmVarDecl *OptLenCand = nullptr;

  for (const ParmVarDecl *P : FD->parameters()) {
    StringRef PName = P->getName();
    std::string TyStr = P->getType().getAsString();

    // optval: prefer named "optval" or type containing "sockptr_t"
    if (!OptValCand) {
      if (PName.equals("optval") || StringRef(TyStr).contains("sockptr_t"))
        OptValCand = P;
    }

    // optlen: prefer named "optlen" or integer type
    if (!OptLenCand) {
      if (PName.equals("optlen") || isIntegerType(P->getType()))
        OptLenCand = P;
    }
  }

  // Require both to be found
  if (!OptValCand || !OptLenCand)
    return false;

  // If name heuristic matches or we found strong signs of setsockopt signature, accept.
  if (!NameHeuristic) {
    // Tighten: require at least explicit optval name or sockptr_t type AND optlen name.
    bool StrongSig = (OptValCand->getName().equals("optval") || StringRef(OptValCand->getType().getAsString()).contains("sockptr_t"))
                     && (OptLenCand->getName().equals("optlen"));
    if (!StrongSig)
      return false;
  }

  OptValParm = OptValCand;
  OptLenParm = OptLenCand;
  return true;
}

bool SAGenTestChecker::exprMentionsOptlenOrMin(const Expr *E, StringRef OptLenName, CheckerContext &C) {
  if (!E)
    return false;
  return ExprHasName(E, OptLenName, C) || ExprHasName(E, "min(", C) || ExprHasName(E, "min_t", C);
}

bool SAGenTestChecker::tryGetDeclRefAndInit(const Expr *E, const VarDecl* &VD, const Expr* &Init) {
  VD = nullptr;
  Init = nullptr;
  if (!E)
    return false;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
    if (const auto *V = dyn_cast<VarDecl>(DRE->getDecl())) {
      VD = V;
      if (V->hasInit())
        Init = V->getInit();
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isLenAssignedFromMinBeforeCall(const VarDecl *LenVar,
                                                      const Stmt *CallS,
                                                      StringRef OptLenName,
                                                      CheckerContext &C) {
  if (!LenVar || !CallS)
    return false;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(CallS, C);
  if (!CS)
    return false;

  const SourceManager &SM = C.getSourceManager();
  SourceLocation CallBegin = CallS->getBeginLoc();

  for (const Stmt *S : CS->body()) {
    if (!S)
      continue;
    SourceLocation SBeg = S->getBeginLoc();
    // Only consider statements before the call.
    if (!SBeg.isValid() || !CallBegin.isValid())
      continue;
    if (!SM.isBeforeInTranslationUnit(SBeg, CallBegin))
      continue;

    const auto *BO = dyn_cast<BinaryOperator>(S);
    if (!BO || !BO->isAssignmentOp())
      continue;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS();

    const auto *LHSRef = dyn_cast<DeclRefExpr>(LHS);
    if (!LHSRef)
      continue;
    const auto *LHVD = dyn_cast<VarDecl>(LHSRef->getDecl());
    if (LHVD != LenVar)
      continue;

    // Check RHS mentions min/min_t and optlen
    if (exprMentionsOptlenOrMin(RHS, OptLenName, C) &&
        (ExprHasName(RHS, "min(", C) || ExprHasName(RHS, "min_t", C))) {
      // Heuristically conclude length is derived from min(optlen, size)
      return true;
    }
  }

  return false;
}

void SAGenTestChecker::reportFixedSizeNoOptlen(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  const Expr *Origin = Call.getOriginExpr();
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "copy_from_sockptr without optlen validation",
      "Copying fixed size from optval without checking optlen can read past user buffer.",
      N);
  if (Origin)
    R->addRange(Origin->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportPartialCopyMin(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  const Expr *Origin = Call.getOriginExpr();
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Partial copy from optval may leave struct uninitialized",
      "Using min(optlen, size) to copy from optval may leave structure fields uninitialized; validate optlen or use a helper.",
      N);
  if (Origin)
    R->addRange(Origin->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned SrcIndex = 0, LenIndex = 0;
  if (!isCopyFromSockptrLike(Call, SrcIndex, LenIndex, C))
    return;

  const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  const ParmVarDecl *OptValParm = nullptr;
  const ParmVarDecl *OptLenParm = nullptr;
  if (!isSetsockoptLikeFunction(FD, OptValParm, OptLenParm))
    return;

  // Extract call arguments
  if (Call.getNumArgs() <= SrcIndex || Call.getNumArgs() <= LenIndex)
    return;

  const Expr *SrcArgE = Call.getArgExpr(SrcIndex);
  const Expr *LenArgE = Call.getArgExpr(LenIndex);
  if (!SrcArgE || !LenArgE || !OptValParm || !OptLenParm)
    return;

  // Ensure the source arg is the setsockopt optval
  if (!ExprHasName(SrcArgE, OptValParm->getName(), C))
    return;

  StringRef OptLenName = OptLenParm->getName();
  // Case 4.2: partial copy using min(optlen, ...)
  bool PartialCopyDetected = false;
  // Direct min(...) in len arg
  if (exprMentionsOptlenOrMin(LenArgE, OptLenName, C) &&
      (ExprHasName(LenArgE, "min(", C) || ExprHasName(LenArgE, "min_t", C))) {
    PartialCopyDetected = true;
  } else {
    // If lenArg is a variable, try its initializer or assignment before the call
    const VarDecl *LenVD = nullptr;
    const Expr *Init = nullptr;
    if (tryGetDeclRefAndInit(LenArgE, LenVD, Init)) {
      if (Init) {
        if (exprMentionsOptlenOrMin(Init, OptLenName, C) &&
            (ExprHasName(Init, "min(", C) || ExprHasName(Init, "min_t", C))) {
          PartialCopyDetected = true;
        }
      } else {
        // No initializer; try to find a previous assignment len = min(..., optlen);
        const Expr *CallE = dyn_cast_or_null<Expr>(Call.getOriginExpr());
        const Stmt *CallS = CallE ? dyn_cast<Stmt>(CallE) : nullptr;
        if (isLenAssignedFromMinBeforeCall(LenVD, CallS, OptLenName, C))
          PartialCopyDetected = true;
      }
    }
  }

  if (PartialCopyDetected) {
    reportPartialCopyMin(Call, C);
    return;
  }

  // Case 4.1: fixed-size copy that doesn't mention optlen at all
  if (!ExprHasName(LenArgE, OptLenName, C)) {
    llvm::APSInt LenVal;
    bool IsConst = EvaluateExprToInt(LenVal, LenArgE, C);

    if (IsConst) {
      reportFixedSizeNoOptlen(Call, C);
      return;
    }

    // If len is a variable, examine its initializer for const/sizeof without optlen
    const VarDecl *VD = nullptr;
    const Expr *Init = nullptr;
    if (tryGetDeclRefAndInit(LenArgE, VD, Init) && Init) {
      bool InitConst = EvaluateExprToInt(LenVal, Init, C);
      bool InitHasSizeof = ExprHasName(Init, "sizeof", C);
      bool InitMentionsOptlen = ExprHasName(Init, OptLenName, C);
      if (!InitMentionsOptlen && (InitConst || InitHasSizeof)) {
        reportFixedSizeNoOptlen(Call, C);
        return;
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe copy_from_sockptr uses in setsockopt handlers without validating optlen, or partial copies using min(optlen, size)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
