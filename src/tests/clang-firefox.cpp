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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h"
#include <memory>
#include <fstream>

using namespace clang;
using namespace ento;
using namespace taint;

// Debug logging helper
static void debugLog(const std::string &msg) {
  std::ofstream logFile("/tmp/firefox_checker_debug.log", std::ios::app);
  if (logFile.is_open()) {
    logFile << "[SAGenTestChecker] " << msg << std::endl;
    logFile.close();
  }
}

namespace {

class SAGenTestChecker : public Checker<check::PostCall> {
private:
  mutable std::unique_ptr<BugType> BugType_;

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(CheckerContext &C, const CallEvent &Call, const char *Msg) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  debugLog("=== SAGenTestChecker ACTIVE: Checking post call in Firefox code ===");

  // Simple checker: Look for calls to potentially unsafe Firefox functions
  if (!Call.getCalleeIdentifier()) {
    debugLog("No callee identifier found, skipping");
    return;
  }

  StringRef FuncName = Call.getCalleeIdentifier()->getName();
  debugLog("ANALYZING FUNCTION CALL: " + FuncName.str());

  // Log source location info for verification
  SourceLocation Loc = Call.getSourceRange().getBegin();
  if (Loc.isValid()) {
    const SourceManager &SM = C.getSourceManager();
    std::string FileName = SM.getFilename(Loc).str();
    unsigned Line = SM.getSpellingLineNumber(Loc);
    debugLog("Location: " + FileName + ":" + std::to_string(Line));
  }

  // Check for some common Firefox patterns that might be problematic
  if (FuncName == "malloc" || FuncName == "calloc" || FuncName == "realloc") {
    debugLog("Found memory allocation function: " + FuncName.str());
    reportBug(C, Call, "Memory allocation detected - consider using Firefox's memory management utilities");
  }

  // Check for direct pointer arithmetic which can be unsafe
  if (FuncName == "memcpy" || FuncName == "strcpy" || FuncName == "strcat") {
    debugLog("Found potentially unsafe string/memory function: " + FuncName.str());
    reportBug(C, Call, "Potentially unsafe memory/string function - consider safer alternatives");
  }

  // Firefox-specific: Check for NS_ function calls (for test verification)
  if (FuncName.startswith("NS_")) {
    debugLog("Found NS_-prefixed function: " + FuncName.str());
    reportBug(C, Call, "NS_ function detected - test verification successful");
  }

  // Firefox-specific: Check for MOZ_ function calls (for test verification)
  if (FuncName.startswith("MOZ_")) {
    debugLog("Found Mozilla-specific function: " + FuncName.str());
    reportBug(C, Call, "Mozilla-specific function detected - test verification successful");
  }

  // Firefox-specific: Check for XPCOM-related patterns
  if (FuncName.contains("XPCOM")) {
    debugLog("Found XPCOM-related function: " + FuncName.str());
    // This is just a demonstration - normally we'd check for specific patterns
  }
}

void SAGenTestChecker::reportBug(CheckerContext &C, const CallEvent &Call, const char *Msg) const {
  debugLog("Reporting bug: " + std::string(Msg));

  if (!BugType_) {
    BugType_ = std::make_unique<clang::ento::BugType>(
        this, "Firefox Safety Check", "Memory/Security Issue"
    );
  }

  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(*BugType_, Msg, N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

// Register plugin using LLVM plugin interface
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  debugLog("*** REGISTERING SAGenTestChecker for Firefox analysis via plugin interface ***");
  registry.addChecker<SAGenTestChecker>("custom.SAGenTest",
                                        "Firefox Safety Checker",
                                        "Checks for Firefox-specific safety issues");
  debugLog("*** SAGenTestChecker registered successfully in plugin registry ***");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
