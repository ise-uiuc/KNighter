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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Track variables used as "partial copy" lengths derived from optlen via min/min_t/sizeof.
REGISTER_SET_WITH_PROGRAMSTATE(PartialLenVars, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PostCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe setsockopt copy_from_sockptr", "API Misuse")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static bool isCopyFromSockptr(const CallEvent &Call, CheckerContext &C);
      static bool isBtCopyFromSockptr(const CallEvent &Call, CheckerContext &C);
      static const FunctionDecl* getEnclosingFunction(const CheckerContext &C);
      static bool isSetsockoptLike(const FunctionDecl *FD);
      static const VarDecl* getAddrOfVar(const Expr *E);
      static const MemRegion* getLenRegionIfDeclRef(const Expr *LenE, CheckerContext &C);
      static bool lenExprSuggestsPartialCopy(const Expr *LenE, CheckerContext &C);
      static bool getDestVarAndSize(const Expr *DstE, CheckerContext &C, const VarDecl* &VD, uint64_t &SizeBytes);
      static bool stmtContains(const Stmt *Outer, const Stmt *Inner, CheckerContext &C);
      static bool hasPrecedingOptlenGuard(const Stmt *CallSite, const VarDecl *VD, CheckerContext &C);

      void reportPartialCopy(const CallEvent &Call, CheckerContext &C) const;
      void reportMissingGuard(const CallEvent &Call, CheckerContext &C) const;
};

// ------------ Helper Implementations ---------------

bool SAGenTestChecker::isCopyFromSockptr(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "copy_from_sockptr", C);
}

bool SAGenTestChecker::isBtCopyFromSockptr(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "bt_copy_from_sockptr", C);
}

const FunctionDecl* SAGenTestChecker::getEnclosingFunction(const CheckerContext &C) {
  const Decl *D = C.getLocationContext()->getDecl();
  return dyn_cast_or_null<FunctionDecl>(D);
}

bool SAGenTestChecker::isSetsockoptLike(const FunctionDecl *FD) {
  if (!FD) return false;
  std::string Name = FD->getNameAsString();
  if (Name.find("setsockopt") != std::string::npos)
    return true;

  for (const ParmVarDecl *P : FD->parameters()) {
    if (const IdentifierInfo *II = P->getIdentifier()) {
      if (II->getName() == "optlen")
        return true;
    }
  }
  return false;
}

const VarDecl* SAGenTestChecker::getAddrOfVar(const Expr *E) {
  if (!E) return nullptr;
  const Expr *IE = E->IgnoreParenCasts();
  const auto *UO = dyn_cast<UnaryOperator>(IE);
  if (!UO || UO->getOpcode() != UO_AddrOf)
    return nullptr;
  const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
    return dyn_cast<VarDecl>(DRE->getDecl());
  }
  return nullptr;
}

const MemRegion* SAGenTestChecker::getLenRegionIfDeclRef(const Expr *LenE, CheckerContext &C) {
  if (!LenE) return nullptr;
  const Expr *IE = LenE->IgnoreParenCasts();
  if (!isa<DeclRefExpr>(IE))
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(IE, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

bool SAGenTestChecker::lenExprSuggestsPartialCopy(const Expr *LenE, CheckerContext &C) {
  if (!LenE) return false;
  bool HasOptlen = ExprHasName(LenE, "optlen", C);
  bool HasMin = ExprHasName(LenE, "min", C) || ExprHasName(LenE, "min_t", C);
  bool HasSizeof = ExprHasName(LenE, "sizeof", C);
  // The strong signal is min/min_t with optlen; also accept patterns that combine optlen and sizeof
  if ((HasMin && HasOptlen) || (HasOptlen && HasSizeof))
    return true;
  return false;
}

bool SAGenTestChecker::getDestVarAndSize(const Expr *DstE, CheckerContext &C, const VarDecl* &VD, uint64_t &SizeBytes) {
  VD = getAddrOfVar(DstE);
  if (!VD) return false;
  ASTContext &ACtx = C.getASTContext();
  CharUnits CU = ACtx.getTypeSizeInChars(VD->getType());
  SizeBytes = static_cast<uint64_t>(CU.getQuantity());
  return true;
}

bool SAGenTestChecker::stmtContains(const Stmt *Outer, const Stmt *Inner, CheckerContext &C) {
  if (!Outer || !Inner) return false;
  const SourceManager &SM = C.getSourceManager();
  SourceLocation OB = Outer->getBeginLoc();
  SourceLocation OE = Outer->getEndLoc();
  SourceLocation IB = Inner->getBeginLoc();

  if (OB.isInvalid() || OE.isInvalid() || IB.isInvalid())
    return false;

  bool BeginBefore = !SM.isBeforeInTranslationUnit(IB, OB);
  bool EndAfter = !SM.isBeforeInTranslationUnit(OE, IB);
  return BeginBefore && EndAfter;
}

bool SAGenTestChecker::hasPrecedingOptlenGuard(const Stmt *CallSite, const VarDecl *VD, CheckerContext &C) {
  if (!CallSite)
    return false;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(CallSite, C);
  if (!CS)
    return false;

  // Find the direct child statement within the compound that contains CallSite
  const Stmt *Current = nullptr;
  for (const Stmt *Child : CS->body()) {
    if (!Child) continue;
    if (stmtContains(Child, CallSite, C)) {
      Current = Child;
      break;
    }
  }
  if (!Current)
    return false;

  // Scan previous statements for a guard mentioning "optlen" and "sizeof"
  for (const Stmt *Child : CS->body()) {
    if (!Child) continue;
    if (Child == Current)
      break;

    if (const auto *IfS = dyn_cast<IfStmt>(Child)) {
      const Expr *Cond = IfS->getCond();
      if (!Cond) continue;
      bool HasOptlen = ExprHasName(Cond, "optlen", C);
      bool HasSizeof = ExprHasName(Cond, "sizeof", C);
      bool HasVarName = VD ? ExprHasName(Cond, VD->getName(), C) : true; // allow type-only sizeof guards
      if (HasOptlen && HasSizeof && HasVarName) {
        return true;
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportPartialCopy(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Partial setsockopt copy; input shorter than struct may leave fields uninitialized", N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportMissingGuard(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing optlen >= sizeof(...) check before copy_from_sockptr", N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

// --------------- Checker Callbacks -----------------

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS) return;
  ProgramStateRef State = C.getState();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD) continue;
    if (!VD->hasInit()) continue;

    const Expr *Init = VD->getInit();
    if (!Init) continue;

    // Seed if initializer involves optlen with min/min_t/sizeof
    bool HasOptlen = ExprHasName(Init, "optlen", C);
    bool HasMin = ExprHasName(Init, "min", C) || ExprHasName(Init, "min_t", C);
    bool HasSizeof = ExprHasName(Init, "sizeof", C);

    if (HasOptlen && (HasMin || HasSizeof)) {
      MemRegionManager &RMgr = C.getSValBuilder().getRegionManager();
      const MemRegion *MR = RMgr.getVarRegion(VD, C.getLocationContext());
      if (MR) {
        MR = MR->getBaseRegion();
        State = State->add<PartialLenVars>(MR);
      }
    }
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  // RHS should indicate a partial length derived from optlen using min/min_t/sizeof
  bool HasOptlen = ExprHasName(RHS, "optlen", C);
  bool HasMin = ExprHasName(RHS, "min", C) || ExprHasName(RHS, "min_t", C);
  bool HasSizeof = ExprHasName(RHS, "sizeof", C);
  if (!(HasOptlen && (HasMin || HasSizeof)))
    return;

  const MemRegion *LHSReg = getMemRegionFromExpr(LHS, C);
  if (!LHSReg) return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) return;

  ProgramStateRef State = C.getState();
  State = State->add<PartialLenVars>(LHSReg);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isCopyFromSockptr(Call, C))
    return;
  if (isBtCopyFromSockptr(Call, C))
    return;

  const FunctionDecl *FD = getEnclosingFunction(C);
  if (!isSetsockoptLike(FD))
    return;

  const Expr *DstE = Call.getArgExpr(0);
  const Expr *LenE = Call.getArgExpr(2);
  if (!DstE || !LenE)
    return;

  // 1) Partial copy patterns
  if (lenExprSuggestsPartialCopy(LenE, C)) {
    reportPartialCopy(Call, C);
    return;
  }

  if (const MemRegion *LenMR = getLenRegionIfDeclRef(LenE, C)) {
    ProgramStateRef State = C.getState();
    if (State->contains<PartialLenVars>(LenMR)) {
      reportPartialCopy(Call, C);
      return;
    }
  }

  // 2) Missing validation for fixed-size copies
  const VarDecl *VD = nullptr;
  uint64_t SizeBytes = 0;
  bool HaveDstAndSize = getDestVarAndSize(DstE, C, VD, SizeBytes);

  // If we have a destination variable and a fixed length, ensure there's a guard.
  if (HaveDstAndSize) {
    // Heuristic: if there's a preceding if-stmt guarding optlen with sizeof, consider safe.
    if (!hasPrecedingOptlenGuard(Call.getOriginExpr(), VD, C)) {
      // If LenE is a constant or contains sizeof, this is clearly a fixed-size copy.
      llvm::APSInt Val;
      bool IsConst = EvaluateExprToInt(Val, LenE, C);
      if (IsConst || ExprHasName(LenE, "sizeof", C)) {
        reportMissingGuard(Call, C);
        return;
      }
      // Even if not constant, copying into &var without optlen guard is suspicious.
      reportMissingGuard(Call, C);
      return;
    }
    // Guard found: do not report.
    return;
  } else {
    // No destination var, but if length looks like a fixed size, still require validation.
    llvm::APSInt Val;
    bool IsConst = EvaluateExprToInt(Val, LenE, C);
    if (IsConst || ExprHasName(LenE, "sizeof", C)) {
      if (!hasPrecedingOptlenGuard(Call.getOriginExpr(), nullptr, C)) {
        reportMissingGuard(Call, C);
        return;
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe copy_from_sockptr use in setsockopt paths (missing optlen validation or partial copy)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
