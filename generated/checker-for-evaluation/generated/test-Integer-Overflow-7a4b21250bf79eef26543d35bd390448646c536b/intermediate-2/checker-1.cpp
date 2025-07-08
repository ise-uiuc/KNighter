#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Lex/Lexer.h"
// Removed non-existent header: #include "clang/StaticAnalyzer/Checkers/Checkers.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker detects unchecked arithmetic on the argument passed to
// roundup_pow_of_two(), which may overflow on 32-bit systems.
class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked arithmetic overflow",
                                        "Arithmetic")) {}

  // Callback: Invoked after a call expression is evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportUncheckedOverflow(const CallEvent &Call, CheckerContext &C,
                               const Expr *ArgE, llvm::APSInt Value) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Use the origin expression to ensure we are dealing with the correct call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Check that the function called is "roundup_pow_of_two"
  if (!ExprHasName(OriginExpr, "roundup_pow_of_two", C))
    return;

  // Retrieve the argument passed to roundup_pow_of_two (expected to be max_entries)
  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return;

  llvm::APSInt EvalRes(/*BitWidth=*/64, /*IsUnsigned=*/true);
  bool Evaluated = EvaluateExprToInt(EvalRes, ArgE, C);

  // Safe threshold is 1UL << 31.
  const uint64_t SafeThreshold = (1UL << 31);

  if (Evaluated) {
    if (EvalRes.getLimitedValue() > SafeThreshold)
      reportUncheckedOverflow(Call, C, ArgE, EvalRes);
  } else {
    // If not evaluable at compile time, try to infer a maximum value from its symbol.
    SVal ArgSVal = Call.getArgSVal(0);
    SymbolRef Sym = ArgSVal.getAsSymbol();
    if (Sym) {
      const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C);
      if (MaxVal && MaxVal->getLimitedValue() > SafeThreshold)
        reportUncheckedOverflow(Call, C, ArgE, *MaxVal);
    }
  }
}

void SAGenTestChecker::reportUncheckedOverflow(const CallEvent &Call, CheckerContext &C,
                                                 const Expr *ArgE, llvm::APSInt Value) const {
  // Generate a non-fatal error node.
  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    SmallString<128> Buf;
    llvm::raw_svector_ostream OS(Buf);
    OS << "Unchecked arithmetic on max_entries in call to roundup_pow_of_two: value ("
       << Value.getLimitedValue() << ") exceeds safe threshold (1UL << 31)";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, OS.str(), N);
    Report->addRange(ArgE->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked arithmetic on attribute max_entries in roundup_pow_of_two that may cause an overflow", "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
