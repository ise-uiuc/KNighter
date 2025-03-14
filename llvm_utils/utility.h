#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_UTILITY_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_UTILITY_H

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/APSIntType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/Expr.h"


using namespace clang;
using namespace ento;

// Evaluate the expression to int type, and store the evaluated result in EvalRes
// Return true if this evaluation succeed.
// Only works for constant values
bool EvaluateExprToInt(llvm::APSInt& EvalRes, const Expr *expr, CheckerContext &C);


// Return the maximal possible value for a given symbol
// Using existing constraints to infer the maximal value
// For example, the maximal value of 'a' may be 10 after the statement "if (a <= 10)"
const llvm::APSInt* inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);


// Get the array size from an expression, and store the result in ArraySize
// Return true if the size is successfully retrieved
// The expression should be the DeclRefExpr of the array
bool getArraySizeFromExpr(llvm::APInt& ArraySize, const Expr *E);


// Get the string size from an expression, and store the result in StringSize
// Return true if the size if successfully retrieved
bool getStringSize(llvm::APInt& StringSize, const Expr *E);

// Get the MemRegion from an expression
// For example, it will return the corresponding MemRegion of the variable "a" given expression of "a"
// Do not pass DeclRefExpr as the parameter!
// Dynamic won't be used in this function, so do not perform IgnoreImplicit() before invoking this function!
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);


// Going upward in an AST tree, and find the Stmt of specific type
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C) {
  if (!S) return nullptr;
  while (!dyn_cast<T>(S)) {
    S = C.getLocationContext()->getParentMap().getParent(S);
    if (!S) return nullptr;
  }
  return dyn_cast<T>(S);
}


// Going downward in an AST tree, and find the Stmt of secific type
// Only return one of the statements if there are many
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S) {
  if (!S) return nullptr;
  if (dyn_cast<T>(S)) return dyn_cast<T>(S);
  for (const Stmt *SubStmt: S->children()) {
    if (dyn_cast<T>(SubStmt))
      return dyn_cast<T>(SubStmt);
    const T* RetVal = findSpecificTypeInChildren<T>(SubStmt);
    if (RetVal) return RetVal;
  }
  return nullptr;
}

/// \brief Determines if the given call is to a function known to dereference
///        certain pointer parameters.
///
/// This function looks up the call's callee name in a known table of functions
/// that definitely dereference one or more of their pointer parameters. If the
/// function is found, it appends the 0-based parameter indices that are dereferenced
/// into \p DerefParams and returns \c true. Otherwise, it returns \c false.
///
/// \param[in] Call        The function call to examine.
/// \param[out] DerefParams
///     A list of parameter indices that the function is known to dereference.
///
/// \return \c true if the function is found in the known-dereference table,
///         \c false otherwise.
bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams);

/// \brief Determines if the source text of an expression contains a specified name.
///
/// This function retrieves the source text corresponding to the provided expression
/// and checks whether that text contains the given \p Name. It leverages Clang's Lexer
/// utilities to extract the text from the expression's source range. If the expression is
/// null, the function returns \c false.
///
/// \param[in] E The expression to inspect.
/// \param[in] Name The name (or substring) to search for within the expression's source text.
/// \param[in] C The checker context, used to access the source manager and language options.
///
/// \return \c true if the expression's source text contains \p Name; otherwise, \c false.
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

#endif
