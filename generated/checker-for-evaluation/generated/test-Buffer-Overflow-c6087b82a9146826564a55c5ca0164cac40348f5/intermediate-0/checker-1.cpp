#include <memory>
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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker intercepts calls to copy_from_user and checks whether
// the number of bytes to be copied exceeds the fixed capacity of the
// destination buffer.
class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Buffer Overflow in copy_from_user")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the originating call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use the utility function to verify that the function called is "copy_from_user".
  if (!ExprHasName(OriginExpr, "copy_from_user", C))
    return;

  // Ensure there are at least three arguments: destination, source, and nbytes.
  if (Call.getNumArgs() < 3)
    return;

  // Obtain the destination buffer expression.
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;

  // Use the utility function to try to extract the fixed array size from the destination.
  llvm::APInt ArraySize(32, 0);
  if (!getArraySizeFromExpr(ArraySize, DestExpr))
    return;

  // Compute effective capacity: fixed size minus one (to allow space for a null terminator).
  uint64_t FixedSize = ArraySize.getZExtValue();
  if (FixedSize == 0)
    return;
  uint64_t EffectiveCapacity = FixedSize - 1;

  // Evaluate the third argument (nbytes) to a concrete integer if possible.
  const Expr *NBytesExpr = Call.getArgExpr(2);
  llvm::APSInt NBytesVal;
  if (!EvaluateExprToInt(NBytesVal, NBytesExpr, C)) {
    // If constant evaluation fails, attempt to determine an upper bound.
    SVal NBytesSVal = Call.getArgSVal(2);
    SymbolRef Sym = NBytesSVal.getAsSymbol();
    if (!Sym)
      return;
    const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C);
    if (!MaxVal)
      return;
    // If the maximum possible value does not exceed the effective capacity, it's safe.
    if (MaxVal->getExtValue() <= EffectiveCapacity)
      return;
    // Otherwise, report a potential overflow.
    if (MaxVal->getExtValue() > EffectiveCapacity) {
      const ExplodedNode *N = C.generateErrorNode();
      if (!N)
        return;
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "Potential buffer overflow: copy_from_user argument may exceed fixed buffer size",
          N);
      Report->addRange(Call.getSourceRange());
      C.emitReport(std::move(Report));
      return;
    }
  } else {
    uint64_t NumBytes = NBytesVal.getExtValue();
    if (NumBytes > EffectiveCapacity) {
      const ExplodedNode *N = C.generateErrorNode();
      if (!N)
        return;
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "Potential buffer overflow: copy_from_user argument exceeds fixed buffer size",
          N);
      Report->addRange(Call.getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential buffer overflow in copy_from_user when nbytes exceeds fixed destination size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
