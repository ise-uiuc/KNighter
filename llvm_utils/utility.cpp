#include "clang/StaticAnalyzer/Checkers/utility.h"

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
  const char *Name;                    ///< The function name.
  llvm::SmallVector<unsigned, 4> Params; ///< The parameter indices that get dereferenced.
};

// This is just an illustrative list. Expand as needed.
const KnownDerefFunction DerefTable[] = {
    // String functions
    {"strcpy",  {0, 1}},  // char *strcpy(char *dest, const char *src);
    {"strcat",  {0, 1}},  // char *strcat(char *dest, const char *src);
    {"strcmp",  {0, 1}},  // int strcmp(const char *s1, const char *s2);
    {"strlen",  {0}},     // size_t strlen(const char *s);
    {"strncpy", {0, 1}},  // char *strncpy(char *dest, const char *src, size_t n);
    {"strncat", {0, 1}},  // char *strncat(char *dest, const char *src, size_t n);

    // Memory functions
    {"memcpy",  {0, 1}},  // void *memcpy(void *dest, const void *src, size_t n);
    {"memmove", {0, 1}},  // void *memmove(void *dest, const void *src, size_t n);
    {"memcmp",  {0, 1}},  // int memcmp(const void *s1, const void *s2, size_t n);
    {"memset",  {0}},     // void *memset(void *s, int c, size_t n);

    // Formatted output
    {"snprintf", {0, 2}}, // int snprintf(char *str, size_t size, const char *format, ...);
    {"sprintf",  {0, 1}}, // int sprintf(char *str, const char *format, ...);

    // Some user-defined or custom system functions
    {"_dev_err",  {2}},    // dev_err(dev, fmt, ptr) -> assume param #2 is dereferenced.
    // Add more as you see fit ...
};

bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    for (const auto &Entry : DerefTable) {
      if (FnName == Entry.Name) {
        // We found the function in our table, copy its param indices
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

  // Use const reference since getSourceManager() returns a const SourceManager.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  // Retrieve the source text corresponding to the expression.
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);

  // Check if the extracted text contains the specified name.
  return ExprText.contains(Name);
}
