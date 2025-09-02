//===- SAGenTestChecker.cpp --------------------------------------*- C++-*-===//
//
//  CSA plugin checker for V8 null dereference bug pattern.
//  Pattern: Detect Cast<T> template calls on potentially null values.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include <fstream>

using namespace clang;
using namespace ento;

namespace {

class V8CastNullChecker : public Checker<check::PreStmt<CallExpr>> {
private:
  mutable std::unique_ptr<BugType> BT;

  void debugLog(const std::string& msg) const {
    std::ofstream logFile("/tmp/v8_checker_debug.log", std::ios::app);
    if (logFile.is_open()) {
      logFile << msg << std::endl;
    }
  }

public:
  V8CastNullChecker() : BT(std::make_unique<BugType>(this, "Cast on potentially null value", "V8Cast")) {
    debugLog("[DEBUG] V8CastNullChecker initialized");
  }

  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;

private:
  bool isCastCall(const CallExpr *CE) const;
  bool couldBeNull(SVal Val, CheckerContext &C) const;
};

void V8CastNullChecker::checkPreStmt(const CallExpr *CE, CheckerContext &C) const {
  debugLog("[DEBUG] checkPreStmt called for CallExpr");

  // Check if this looks like a Cast call
  if (!isCastCall(CE)) {
    debugLog("[DEBUG] Not a Cast call, skipping");
    return;
  }

  debugLog("[DEBUG] Found Cast call! Analyzing arguments...");

  // Check all arguments for potential null values
  for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
    const Expr *ArgExpr = CE->getArg(i);
    SVal ArgVal = C.getSVal(ArgExpr);

    debugLog("[DEBUG] Checking argument " + std::to_string(i));

    if (couldBeNull(ArgVal, C)) {
      debugLog("[DEBUG] Argument " + std::to_string(i) + " could be null! Reporting bug...");

      // Create bug report
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto R = std::make_unique<PathSensitiveBugReport>(*BT,
        "Cast operation on value that may be null", N);
      R->addRange(CE->getSourceRange());
      C.emitReport(std::move(R));
      return;
    } else {
      debugLog("[DEBUG] Argument " + std::to_string(i) + " seems safe");
    }
  }

  debugLog("[DEBUG] All arguments seem safe");
}

bool V8CastNullChecker::isCastCall(const CallExpr *CE) const {
  // Method 1: Check direct callee name
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    std::string name = FD->getName().str();
    debugLog("[DEBUG] Direct callee name: " + name);

    if (name.find("Cast") != std::string::npos) {
      debugLog("[DEBUG] Found Cast via direct callee name");
      return true;
    }

    // Check qualified name for template instantiations
    std::string qualName = FD->getQualifiedNameAsString();
    debugLog("[DEBUG] Qualified name: " + qualName);

    if (qualName.find("Cast") != std::string::npos) {
      debugLog("[DEBUG] Found Cast via qualified name");
      return true;
    }
  }

  // Method 2: Check if this is a template function call expression
  if (const auto *DTCE = dyn_cast<DependentScopeDeclRefExpr>(CE->getCallee()->IgnoreParenCasts())) {
    if (DTCE->getDeclName().getAsString().find("Cast") != std::string::npos) {
      debugLog("[DEBUG] Found Cast via dependent template name");
      return true;
    }
  }

  // Method 3: Check unresolved lookup expressions (common for templates)
  if (const auto *ULE = dyn_cast<UnresolvedLookupExpr>(CE->getCallee()->IgnoreParenCasts())) {
    if (ULE->getName().getAsString().find("Cast") != std::string::npos) {
      debugLog("[DEBUG] Found Cast via unresolved lookup");
      return true;
    }
  }

  debugLog("[DEBUG] No Cast pattern found");
  return false;
}

bool V8CastNullChecker::couldBeNull(SVal Val, CheckerContext &C) const {
  debugLog("[DEBUG] Checking if value could be null");

  // If it's not a defined value, be conservative
  auto DV = Val.getAs<DefinedOrUnknownSVal>();
  if (!DV) {
    debugLog("[DEBUG] Not a defined value - could be null");
    return true;
  }

  ProgramStateRef State = C.getState();

  // For location values, check if they can be null
  if (isa<Loc>(*DV)) {
    debugLog("[DEBUG] Is a location value, checking null possibility");

    // Try to assume it's null
    ProgramStateRef NullState = State->assume(*DV, false);
    if (NullState) {
      debugLog("[DEBUG] Value can be null");
      return true;
    }
  }

  // Check for zero constants
  if (Val.isZeroConstant()) {
    debugLog("[DEBUG] Is zero constant");
    return true;
  }

  // Check for unknown values
  if (Val.isUnknown()) {
    debugLog("[DEBUG] Is unknown value");
    return true;
  }

  debugLog("[DEBUG] Value appears non-null");
  return false;
}

} // end anonymous namespace

// ----- Plugin registration -----
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<V8CastNullChecker>(
      "custom.SAGenTestChecker",
      "Warns on Cast operations that may receive null values", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
