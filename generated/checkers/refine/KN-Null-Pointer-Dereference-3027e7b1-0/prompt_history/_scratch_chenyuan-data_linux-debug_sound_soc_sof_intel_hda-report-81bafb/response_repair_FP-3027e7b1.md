Refinement Plan:
- Root cause: The checker conflates loading a tracked pointer value through a double pointer (e.g., "*out = p") with dereferencing the tracked pointer itself (e.g., "*p" or "p[i]"). This happens because we use Region2SymMap in checkLocation to recover a tracked SymbolRef from the region of the base expression being dereferenced, which in double-pointer cases points to the storage holding the tracked pointer, not the tracked pointer itself. The checker then mistakenly reports a dereference even when the tracked pointer is immediately NULL-checked.
- Fix 1: In checkLocation, only report a dereference when the base expression being dereferenced (PtrE) has exactly one level of indirection (pointer depth == 1). This excludes cases such as "*char**" where the load only reads the pointer value (and is not a dereference of the tracked pointer).
- Fix 2: Make isDevmKasprintf match the callee by identifier name (getCalleeIdentifier) instead of substring search with ExprHasName to avoid spurious matches.
- Fix 3: Keep Region2SymMap propagation for arguments and checks (checkPreCall/checkBranchCondition), but avoid using Region2SymMap in a way that causes the double-pointer deref misinterpretation in checkLocation.
- Edge cases: The refinement still detects real dereferences like name[i] or *name for char* as intended. Passing the tracked pointer to functions known to dereference (e.g., ice_ptp_auxbus_create_id_table) and logging with literal formats containing %s is still caught. It will not report when only storing the pointer via an out-parameter or when the pointer is immediately NULL-checked.
- Compatibility: Uses Clang-18 APIs only; no includes removed.

Refined Code:
```cpp
#include <memory>
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"

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

using namespace clang;
using namespace ento;
using namespace taint;

// Program-state: Track symbols returned by devm_kasprintf that might be NULL and are unchecked.
// Key: SymbolRef of the pointer value; Value: false = not checked yet, true = checked.
REGISTER_MAP_WITH_PROGRAMSTATE(PossibleNullSymMap, SymbolRef, bool)

// Track which pointer SymbolRef is currently stored in a specific region (e.g., a variable or field).
REGISTER_MAP_WITH_PROGRAMSTATE(Region2SymMap, const MemRegion*, SymbolRef)

// Utility Functions (provided)
// Going upward in an AST tree, and find the Stmt of a specific type
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

// Going downward in an AST tree, and find the Stmt of a secific type
// Only return one of the statements if there are many
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

// The expression should be the DeclRefExpr of the array
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
  const char *Name;                    ///< The function name.
  llvm::SmallVector<unsigned, 4> Params; ///< The parameter indices that get dereferenced.
};

bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams) {
  // No external table is provided; conservatively return false.
  (void)Call;
  (void)DerefParams;
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
class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::BranchCondition,
    check::Location,
    check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() {
        BT = std::make_unique<BugType>(this,
              "Missing NULL-check after devm_kasprintf()", "API Misuse");
      }

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:

      // Helpers
      static bool isDevmKasprintf(const CallEvent &Call, CheckerContext &C);
      static SymbolRef getSymbolFromSValOrExpr(SVal SV, const Expr *E, CheckerContext &C);
      static ProgramStateRef setChecked(ProgramStateRef State, SymbolRef Sym);
      static bool isUncheckedPossiblyNull(ProgramStateRef State, SymbolRef Sym);
      static ProgramStateRef bindRegionToSymbol(ProgramStateRef State, const MemRegion *Dst, SymbolRef Sym);
      static ProgramStateRef clearRegionBinding(ProgramStateRef State, const MemRegion *Dst);
      static SymbolRef getSymbolFromRegion(ProgramStateRef State, const MemRegion *R);
      void report(CheckerContext &C, const Stmt *UseSite, StringRef Why) const;

      // Determine if this call is known to dereference certain param indices.
      static bool callIsKnownToDeref(const CallEvent &Call,
                                     CheckerContext &C,
                                     llvm::SmallVectorImpl<unsigned> &Params);

      // Specialized detection for dev_* and printk* to reduce FPs:
      // Consider deref only if a literal format contains "%s", and only
      // as many arguments as "%s" occurrences.
      static bool loggingFormatDereferencesString(const CallEvent &Call, CheckerContext &C,
                                                  unsigned &FormatIndex, unsigned &NumStrArgs);

      // Strip common wrappers in conditions, e.g., likely/unlikely calls.
      static const Expr *stripConditionWrappers(const Expr *E, CheckerContext &C);

      // Handle IS_ERR / IS_ERR_OR_NULL wrappers to mark checks.
      static bool isIS_ERR_LikeCall(const Expr *E, CheckerContext &C, const Expr *&PtrArg);

      // Helper: compute pointer depth (number of pointer-indirections)
      static unsigned pointerDepth(QualType T);
};

///////////////////////
// Helper definitions //
///////////////////////

bool SAGenTestChecker::isDevmKasprintf(const CallEvent &Call, CheckerContext &C) {
  (void)C;
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == "devm_kasprintf";
  return false;
}

SymbolRef SAGenTestChecker::getSymbolFromSValOrExpr(SVal SV, const Expr *E, CheckerContext &C) {
  if (SymbolRef S = SV.getAsSymbol())
    return S;

  const MemRegion *MR = nullptr;
  if (E)
    MR = getMemRegionFromExpr(E, C);
  if (!MR)
    MR = SV.getAsRegion();

  if (!MR)
    return nullptr;

  ProgramStateRef State = C.getState();
  if (SymbolRef const *PS = State->get<Region2SymMap>(MR))
    return *PS;

  return nullptr;
}

ProgramStateRef SAGenTestChecker::setChecked(ProgramStateRef State, SymbolRef Sym) {
  if (!Sym) return State;
  if (const bool *Checked = State->get<PossibleNullSymMap>(Sym)) {
    if (!*Checked)
      State = State->set<PossibleNullSymMap>(Sym, true);
  }
  return State;
}

bool SAGenTestChecker::isUncheckedPossiblyNull(ProgramStateRef State, SymbolRef Sym) {
  if (!Sym) return false;
  if (const bool *Checked = State->get<PossibleNullSymMap>(Sym)) {
    return *Checked == false;
  }
  return false;
}

ProgramStateRef SAGenTestChecker::bindRegionToSymbol(ProgramStateRef State, const MemRegion *Dst, SymbolRef Sym) {
  if (!Dst || !Sym) return State;
  return State->set<Region2SymMap>(Dst, Sym);
}

ProgramStateRef SAGenTestChecker::clearRegionBinding(ProgramStateRef State, const MemRegion *Dst) {
  if (!Dst) return State;
  return State->remove<Region2SymMap>(Dst);
}

SymbolRef SAGenTestChecker::getSymbolFromRegion(ProgramStateRef State, const MemRegion *R) {
  if (!R) return nullptr;
  if (SymbolRef const *PS = State->get<Region2SymMap>(R))
    return *PS;
  return nullptr;
}

void SAGenTestChecker::report(CheckerContext &C, const Stmt *UseSite, StringRef Why) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  llvm::SmallString<128> Msg;
  Msg += "Missing NULL-check after devm_kasprintf(); ";
  Msg += Why;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (UseSite)
    Rpt->addRange(UseSite->getSourceRange());
  C.emitReport(std::move(Rpt));
}

static unsigned countPercentS(StringRef S) {
  unsigned Cnt = 0;
  for (size_t i = 0; i + 1 < S.size(); ++i) {
    if (S[i] == '%') {
      if (S[i + 1] == '%') { // escaped percent
        ++i;
        continue;
      }
      if (S[i + 1] == 's')
        ++Cnt;
      ++i;
    }
  }
  return Cnt;
}

bool SAGenTestChecker::loggingFormatDereferencesString(const CallEvent &Call,
                                                       CheckerContext &C,
                                                       unsigned &FormatIndex,
                                                       unsigned &NumStrArgs) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  bool IsDev = ExprHasName(Origin, "dev_err", C) ||
               ExprHasName(Origin, "dev_warn", C) ||
               ExprHasName(Origin, "dev_info", C) ||
               ExprHasName(Origin, "dev_dbg", C);
  bool IsPrintk = ExprHasName(Origin, "printk", C) ||
                  ExprHasName(Origin, "pr_err", C) ||
                  ExprHasName(Origin, "pr_warn", C) ||
                  ExprHasName(Origin, "pr_info", C) ||
                  ExprHasName(Origin, "pr_debug", C);
  if (!IsDev && !IsPrintk)
    return false;

  FormatIndex = IsDev ? 1u : 0u;
  if (Call.getNumArgs() <= FormatIndex)
    return false;

  const Expr *FmtE = Call.getArgExpr(FormatIndex);
  if (!FmtE)
    return false;

  if (const auto *SL = dyn_cast<StringLiteral>(FmtE->IgnoreImpCasts())) {
    StringRef S = SL->getString();
    unsigned Cnt = countPercentS(S);
    if (Cnt == 0)
      return false;
    NumStrArgs = Cnt;
    return true;
  }

  // Non-literal format: be conservative and RETURN FALSE to reduce FPs.
  return false;
}

bool SAGenTestChecker::callIsKnownToDeref(const CallEvent &Call,
                                          CheckerContext &C,
                                          llvm::SmallVectorImpl<unsigned> &Params) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // String and memory functions
  if (ExprHasName(Origin, "strlen", C)) { Params.push_back(0); return true; }
  if (ExprHasName(Origin, "strnlen", C)) { Params.push_back(0); return true; }
  if (ExprHasName(Origin, "strcmp", C)) { Params.push_back(0); Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strncmp", C)) { Params.push_back(0); Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strcpy", C)) { Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strncpy", C)) { Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strcat", C)) { Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strncat", C)) { Params.push_back(1); return true; }

  // Kernel logging helpers: consider deref only if format literal contains "%s"
  unsigned FmtIdx = 0, NumS = 0;
  if (loggingFormatDereferencesString(Call, C, FmtIdx, NumS)) {
    unsigned N = Call.getNumArgs();
    unsigned StartIdx = FmtIdx + 1;
    for (unsigned i = 0; i < NumS && (StartIdx + i) < N; ++i)
      Params.push_back(StartIdx + i);
    return !Params.empty();
  }

  // Project-specific helper in the buggy code:
  // int ice_ptp_auxbus_create_id_table(struct ice_pf *pf, char *name);
  if (ExprHasName(Origin, "ice_ptp_auxbus_create_id_table", C)) {
    if (Call.getNumArgs() >= 2) {
      Params.push_back(1); // 'name' parameter
      return true;
    }
  }

  // snprintf-like: format at index 2; varargs can deref string pointers, but
  // we only consider if format literal contains "%s".
  if (ExprHasName(Origin, "snprintf", C) || ExprHasName(Origin, "vsnprintf", C)) {
    if (Call.getNumArgs() >= 3) {
      const Expr *FmtE = Call.getArgExpr(2);
      if (const auto *SL = FmtE ? dyn_cast<StringLiteral>(FmtE->IgnoreImpCasts()) : nullptr) {
        unsigned NumSfmt = countPercentS(SL->getString());
        if (NumSfmt > 0) {
          for (unsigned i = 0; i < NumSfmt; ++i) {
            unsigned Idx = 3 + i;
            if (Idx < Call.getNumArgs())
              Params.push_back(Idx);
          }
          return !Params.empty();
        }
      }
    }
  }

  if (functionKnownToDeref(Call, Params))
    return true;

  return false;
}

bool SAGenTestChecker::isIS_ERR_LikeCall(const Expr *E, CheckerContext &C, const Expr *&PtrArg) {
  PtrArg = nullptr;
  E = E ? E->IgnoreParenCasts() : nullptr;
  const auto *CE = dyn_cast_or_null<CallExpr>(E);
  if (!CE)
    return false;

  const Expr *Origin = CE->getCallee();
  if (!Origin)
    return false;

  // Match common wrappers used in the kernel.
  if (ExprHasName(Origin, "IS_ERR_OR_NULL", C) || ExprHasName(Origin, "IS_ERR", C)) {
    if (CE->getNumArgs() >= 1) {
      PtrArg = CE->getArg(0)->IgnoreParenCasts();
      return true;
    }
  }
  return false;
}

const Expr *SAGenTestChecker::stripConditionWrappers(const Expr *E, CheckerContext &C) {
  if (!E) return E;

  // Strip parens, implicit casts, cleanups.
  const Expr *Cur = E->IgnoreParenImpCasts();

  // Strip likely/unlikely/__builtin_expect wrappers.
  while (true) {
    Cur = Cur->IgnoreParenImpCasts();
    const auto *CE = dyn_cast<CallExpr>(Cur);
    if (!CE)
      break;
    const Expr *Callee = CE->getCallee();
    if (!Callee)
      break;
    if (ExprHasName(Callee, "likely", C) || ExprHasName(Callee, "unlikely", C) ||
        ExprHasName(Callee, "__builtin_expect", C)) {
      if (CE->getNumArgs() >= 1) {
        Cur = CE->getArg(0)->IgnoreParenImpCasts();
        continue;
      }
    }
    break;
  }
  return Cur;
}

unsigned SAGenTestChecker::pointerDepth(QualType T) {
  unsigned Depth = 0;
  QualType Cur = T;
  while (!Cur.isNull() && Cur->isPointerType()) {
    ++Depth;
    Cur = Cur->getPointeeType();
  }
  return Depth;
}

//////////////////////
// Checker callbacks //
//////////////////////

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isDevmKasprintf(Call, C))
    return;

  ProgramStateRef State = C.getState();

  // Track the return value symbol as possibly NULL and unchecked.
  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  State = State->set<PossibleNullSymMap>(Sym, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 8> DerefParams;
  if (!callIsKnownToDeref(Call, C, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    SVal ArgSV = Call.getArgSVal(Idx);
    SymbolRef Sym = getSymbolFromSValOrExpr(ArgSV, ArgE, C);

    if (!Sym)
      continue;

    if (isUncheckedPossiblyNull(State, Sym)) {
      report(C, Call.getOriginExpr(), "pointer may be NULL and is dereferenced");
      // Mark as checked to avoid duplicate reports on the same path.
      State = setChecked(State, Sym);
      C.addTransition(State);
      // Continue to check other args.
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  // Normalize condition: strip wrappers and casts.
  CondE = stripConditionWrappers(CondE, C);

  // Pattern: if (!ptr) or if (!IS_ERR_OR_NULL(ptr))
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = stripConditionWrappers(UO->getSubExpr()->IgnoreParenCasts(), C);
      const Expr *PtrFromISERR = nullptr;
      if (isIS_ERR_LikeCall(SubE, C, PtrFromISERR) && PtrFromISERR) {
        SVal SubSV = State->getSVal(PtrFromISERR, C.getLocationContext());
        SymbolRef Sym = getSymbolFromSValOrExpr(SubSV, PtrFromISERR, C);
        if (Sym)
          State = setChecked(State, Sym);
      } else {
        if (SubE) {
          SVal SubSV = State->getSVal(SubE, C.getLocationContext());
          SymbolRef Sym = getSymbolFromSValOrExpr(SubSV, SubE, C);
          if (Sym)
            State = setChecked(State, Sym);
        }
      }
    }
  }
  // Pattern: if (ptr == NULL) or if (ptr != NULL)
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = stripConditionWrappers(BO->getLHS()->IgnoreParenCasts(), C);
      const Expr *RHS = stripConditionWrappers(BO->getRHS()->IgnoreParenCasts(), C);
      ASTContext &ACtx = C.getASTContext();

      bool LHSIsNull = LHS && LHS->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS && RHS->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull);

      const Expr *PtrE = nullptr;
      if (LHSIsNull && !RHSIsNull) PtrE = RHS;
      if (!LHSIsNull && RHSIsNull) PtrE = LHS;

      if (PtrE) {
        SVal PSV = State->getSVal(PtrE, C.getLocationContext());
        SymbolRef Sym = getSymbolFromSValOrExpr(PSV, PtrE, C);
        if (Sym)
          State = setChecked(State, Sym);
      }
    }
  }
  // Pattern: if (IS_ERR_OR_NULL(ptr)) or if (IS_ERR(ptr))
  else if (const auto *CE = dyn_cast<CallExpr>(CondE)) {
    const Expr *PtrE = nullptr;
    if (isIS_ERR_LikeCall(CE, C, PtrE) && PtrE) {
      SVal PSV = State->getSVal(PtrE, C.getLocationContext());
      SymbolRef Sym = getSymbolFromSValOrExpr(PSV, PtrE, C);
      if (Sym)
        State = setChecked(State, Sym);
    } else {
      // Pattern: if (ptr)
      SVal CSV = State->getSVal(CondE, C.getLocationContext());
      SymbolRef Sym = getSymbolFromSValOrExpr(CSV, CondE, C);
      if (Sym) {
        State = setChecked(State, Sym);
      }
    }
  }
  // Pattern: if (ptr)
  else {
    SVal CSV = State->getSVal(CondE, C.getLocationContext());
    SymbolRef Sym = getSymbolFromSValOrExpr(CSV, CondE, C);
    if (Sym) {
      State = setChecked(State, Sym);
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Only report on clear dereference expressions to avoid FPs from generic loads.
  if (!IsLoad || !S)
    return;

  ProgramStateRef State = C.getState();
  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return;
  E = E->IgnoreParenCasts();

  const Expr *PtrE = nullptr;
  bool IsArraySubscript = false;

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref)
      PtrE = UO->getSubExpr()->IgnoreParenCasts();
  } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    PtrE = ASE->getBase()->IgnoreParenCasts();
    IsArraySubscript = true;
  }

  if (!PtrE)
    return;

  // Only consider dereference of a single-level pointer. This avoids treating
  // loads through a double-pointer (e.g., "*out") as dereferences of the tracked
  // pointer value stored in that memory.
  if (pointerDepth(PtrE->getType()) != 1)
    return;

  // Get the symbol of the pointer value we are dereferencing: either directly
  // from the SVal, or from a tracked region binding of the base expression.
  SVal PSV = State->getSVal(PtrE, C.getLocationContext());
  SymbolRef Sym = PSV.getAsSymbol();
  if (!Sym)
    Sym = getSymbolFromSValOrExpr(PSV, PtrE, C);

  if (!Sym)
    return;

  if (isUncheckedPossiblyNull(State, Sym)) {
    report(C, S, "pointer may be NULL and is dereferenced");
    State = setChecked(State, Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  // Try to learn the symbol on RHS.
  SymbolRef RHSym = Val.getAsSymbol();

  if (!RHSym && StoreE) {
    // If RHS is not a symbol directly, but it's a variable/field holding a tracked symbol, propagate it.
    if (const Expr *E = dyn_cast<Expr>(StoreE)) {
      if (const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenCasts())) {
        if (BO->isAssignmentOp()) {
          const Expr *RHSExpr = BO->getRHS();
          const MemRegion *RHSRegion = getMemRegionFromExpr(RHSExpr, C);
          if (RHSRegion) {
            if (SymbolRef S = getSymbolFromRegion(State, RHSRegion))
              RHSym = S;
          }
        }
      } else if (const auto *DS = dyn_cast<DeclStmt>(E)) {
        // Initializer in a declaration: handle "T x = y;" case
        for (const Decl *D : DS->decls()) {
          if (const auto *VD = dyn_cast<VarDecl>(D)) {
            if (const Expr *Init = VD->getInit()) {
              const MemRegion *RHSRegion = getMemRegionFromExpr(Init, C);
              if (RHSRegion) {
                if (SymbolRef S = getSymbolFromRegion(State, RHSRegion))
                  RHSym = S;
              }
            }
          }
        }
      }
    }
  }

  if (LHS) {
    if (RHSym) {
      State = bindRegionToSymbol(State, LHS, RHSym);
    } else {
      // Clearing binding on non-symbol assignments (e.g., string literal, NULL, other constants)
      State = clearRegionBinding(State, LHS);
    }
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect missing NULL-check after devm_kasprintf and subsequent use",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
