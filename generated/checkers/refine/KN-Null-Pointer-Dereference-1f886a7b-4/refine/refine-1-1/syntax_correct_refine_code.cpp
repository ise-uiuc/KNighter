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
#include <memory>
#include <array>

using namespace clang;
using namespace ento;
using namespace taint;

// Track unchecked symbols returned by devm_kzalloc.
REGISTER_SET_WITH_PROGRAMSTATE(UncheckedDevmPtrSyms, SymbolRef)

// Utility Functions (provided)
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
  Expr::EvalResult ExprRes;
  if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
    EvalRes = ExprRes.Val.getInt();
    return true;
  }
  return false;
}

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
  return maxVal;
}

bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = ArrayType->getSize();
        return true;
      }
    }
  }
  return false;
}

bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
  if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
    StringSize = llvm::APInt(32, SL->getLength());
    return true;
  }
  return false;
}

const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}

struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};

bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  // No known dereferencing functions are specified; keep the table empty.
  static const std::array<KnownDerefFunction, 0> DerefTable = {};

  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    for (const auto &Entry : DerefTable) {
      if (FnName.equals(Entry.Name)) {
        DerefParams.append(Entry.Params.begin(), Entry.Params.end());
        return true;
      }
    }
  }
  return false;
}

bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);

  return ExprText.contains(Name);
}

namespace {

class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::BranchCondition,
      check::Location
    > {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Possible NULL dereference", "Memory Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Extract the base pointer symbol that is being dereferenced by statement S.
  SymbolRef getDereferencedBaseSymbol(const Stmt *S, SVal Loc, CheckerContext &C) const;

  void reportBug(CheckerContext &C, const Stmt *S) const;

  // Helpers to reason about conditions and symbols.
  static const Expr *stripParensAndCasts(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  // If condition is wrapped in __builtin_expect (i.e., likely/unlikely), unwrap it.
  static const Expr *unwrapBuiltinExpect(const Expr *E) {
    E = stripParensAndCasts(E);
    if (!E)
      return nullptr;

    if (const auto *CE = dyn_cast<CallExpr>(E)) {
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        if (const IdentifierInfo *ID = FD->getIdentifier()) {
          StringRef Name = ID->getName();
          if (Name.equals("__builtin_expect")) {
            if (CE->getNumArgs() >= 1)
              return stripParensAndCasts(CE->getArg(0));
          }
        }
      }
    }
    return E;
  }

  // Try to get a symbol from an expression that denotes a pointer rvalue.
  SymbolRef getSymbolFromExpr(const Expr *E, CheckerContext &C) const {
    if (!E) return nullptr;
    ProgramStateRef State = C.getState();
    const LocationContext *LCtx = C.getLocationContext();
    E = stripParensAndCasts(E);
    SVal SV = State->getSVal(E, LCtx);

    if (SymbolRef Sym = SV.getAsSymbol())
      return Sym;

    if (const MemRegion *MR = SV.getAsRegion()) {
      MR = MR->getBaseRegion();
      if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
        return SR->getSymbol();
    }
    return nullptr;
  }

  // Collect symbols that are explicitly NULL-checked in the condition.
  void collectNullCheckedSymbols(const Expr *CondE,
                                 CheckerContext &C,
                                 llvm::SmallVectorImpl<SymbolRef> &Out) const {
    if (!CondE) return;

    // Unwrap builtin_expect (likely/unlikely) and ignore parens/casts.
    CondE = unwrapBuiltinExpect(CondE);
    CondE = stripParensAndCasts(CondE);
    if (!CondE) return;

    // Handle logical combinations: (A && B), (A || B).
    if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
      if (BO->isLogicalOp()) {
        collectNullCheckedSymbols(BO->getLHS(), C, Out);
        collectNullCheckedSymbols(BO->getRHS(), C, Out);
        return;
      }

      // Handle ptr == NULL or ptr != NULL
      if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
        const Expr *LHS = stripParensAndCasts(BO->getLHS());
        const Expr *RHS = stripParensAndCasts(BO->getRHS());
        if (!LHS || !RHS) return;

        bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                 Expr::NPC_ValueDependentIsNull);
        bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                 Expr::NPC_ValueDependentIsNull);

        const Expr *PtrExpr = nullptr;
        if (LHSIsNull && !RHSIsNull)
          PtrExpr = RHS;
        else if (RHSIsNull && !LHSIsNull)
          PtrExpr = LHS;

        if (PtrExpr) {
          if (SymbolRef S = getSymbolFromExpr(PtrExpr, C))
            Out.push_back(S);
        }
        return;
      }
    }

    // Handle '!ptr' or nested '!!ptr' etc.
    if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
      if (UO->getOpcode() == UO_LNot) {
        const Expr *Sub = stripParensAndCasts(UO->getSubExpr());
        // If it is another !, recurse to peel
        if (const auto *InnerUO = dyn_cast<UnaryOperator>(Sub)) {
          if (InnerUO->getOpcode() == UO_LNot) {
            collectNullCheckedSymbols(InnerUO->getSubExpr(), C, Out);
            return;
          }
        }
        // Otherwise the subexpr is the pointer being tested for falsiness
        if (SymbolRef S = getSymbolFromExpr(Sub, C))
          Out.push_back(S);
        return;
      }
    }

    // We intentionally DO NOT treat bare "if (ptr)" as a NULL check here,
    // because without branch sensitivity we can't safely clear the unchecked
    // state on both branches. This avoids masking real bugs.
  }
};

SymbolRef SAGenTestChecker::getDereferencedBaseSymbol(const Stmt *S, SVal Loc,
                                                      CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // Case 1: p->field
  if (const auto *ME = dyn_cast_or_null<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *BaseE = ME->getBase();
      if (BaseE) {
        SVal BaseV = State->getSVal(BaseE, LCtx);
        if (SymbolRef Sym = BaseV.getAsSymbol())
          return Sym;
        if (const MemRegion *MR = BaseV.getAsRegion()) {
          MR = MR->getBaseRegion();
          if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
            return SR->getSymbol();
        }
      }
    }
  }

  // Case 2: *p
  if (const auto *UO = dyn_cast_or_null<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *BaseE = UO->getSubExpr();
      if (BaseE) {
        SVal BaseV = State->getSVal(BaseE, LCtx);
        if (SymbolRef Sym = BaseV.getAsSymbol())
          return Sym;
        if (const MemRegion *MR = BaseV.getAsRegion()) {
          MR = MR->getBaseRegion();
          if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
            return SR->getSymbol();
        }
      }
    }
  }

  // Fallback: derive from location region.
  if (const MemRegion *MR = Loc.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
      return SR->getSymbol();
  }

  return nullptr;
}

void SAGenTestChecker::reportBug(CheckerContext &C, const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "devm_kzalloc() result may be NULL and is dereferenced without check", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Precisely track calls to devm_kzalloc (by callee identifier).
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID || !ID->getName().equals("devm_kzalloc"))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    State = State->add<UncheckedDevmPtrSyms>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  llvm::SmallVector<SymbolRef, 4> CheckedSyms;
  collectNullCheckedSymbols(CondE, C, CheckedSyms);

  if (CheckedSyms.empty())
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;
  for (SymbolRef S : CheckedSyms) {
    if (State->contains<UncheckedDevmPtrSyms>(S)) {
      State = State->remove<UncheckedDevmPtrSyms>(S);
      Changed = true;
    }
  }
  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  SymbolRef BaseSym = getDereferencedBaseSymbol(S, Loc, C);
  if (!BaseSym)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<UncheckedDevmPtrSyms>(BaseSym)) {
    reportBug(C, S);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect dereference of devm_kzalloc() result without NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
