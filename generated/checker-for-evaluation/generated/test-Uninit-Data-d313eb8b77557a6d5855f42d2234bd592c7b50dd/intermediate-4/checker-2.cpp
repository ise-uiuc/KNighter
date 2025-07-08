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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/ADT/APInt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map for tracking whether a structure has been zeroed out.
REGISTER_MAP_WITH_PROGRAMSTATE(StructInitMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType("Uninitialized Padding Copy", "custom.SAGenTestChecker")) {}

  // Callback: after a function call is evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback: before a function call is evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportUninitStructure(const CallEvent &Call, CheckerContext &C,
                             const MemRegion *MR) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Intercept memset calls.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "memset", C))
    return;

  // We expect memset(dest, c, n) => arg0: dest, arg2: size.
  if (Call.getNumArgs() < 3)
    return;

  // Retrieve the destination memory region.
  const Expr *DestExpr = Call.getArgExpr(0);
  const MemRegion *DestMR = getMemRegionFromExpr(DestExpr, C);
  if (!DestMR)
    return;
  DestMR = DestMR->getBaseRegion();

  // Try to evaluate the memset size (third argument).
  llvm::APSInt SizeVal;
  const Expr *SizeExpr = Call.getArgExpr(2);
  if (!EvaluateExprToInt(SizeVal, SizeExpr, C))
    return; // Undecidable size, do not update state.

  // Try to deduce the complete size of the structure being zeroed.
  // We check if the destination expression corresponds to a local variable.
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(DestExpr->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType VarType = VD->getType();
      if (const RecordType *RT = VarType->getAs<RecordType>()) {
        // Get the size of the record (in bits) then convert to bytes.
        uint64_t TypeSizeBits = C.getASTContext().getTypeSize(VarType);
        uint64_t TypeSizeBytes = TypeSizeBits / 8;
        // Compare with the evaluated memset size.
        if (SizeVal.getZExtValue() == TypeSizeBytes) {
          // Mark the structure region as fully initialized (zeroed).
          ProgramStateRef State = C.getState();
          State = State->set<StructInitMap>(DestMR, true);
          C.addTransition(State);
        }
      }
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Intercept calls to functions that copy data to user space.
  // We check for copy_to_user and copy_to_user_iter.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  bool isCopyToUser = (ExprHasName(OriginExpr, "copy_to_user", C) ||
                       ExprHasName(OriginExpr, "copy_to_user_iter", C));
  if (!isCopyToUser)
    return;

  // For copy_to_user, the source buffer is the second argument (index 1).
  if (Call.getNumArgs() < 2)
    return;

  const Expr *SrcExpr = Call.getArgExpr(1);
  const MemRegion *SrcMR = getMemRegionFromExpr(SrcExpr, C);
  if (!SrcMR)
    return;
  SrcMR = SrcMR->getBaseRegion();

  ProgramStateRef State = C.getState();
  const bool *IsZeroed = State->get<StructInitMap>(SrcMR);
  // If the region was either not memset or not fully zeroed, it may contain padding.
  if (!IsZeroed || (*IsZeroed == false)) {
    reportUninitStructure(Call, C, SrcMR);
  }
}

void SAGenTestChecker::reportUninitStructure(const CallEvent &Call, CheckerContext &C,
                                               const MemRegion *MR) const {
  // Report the potential bug: structure with uninitialized padding is being copied.
  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Structure with potential uninitialized padding copied to user space", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects copying of structures with uninitialized (non-zeroed) padding to user space",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
