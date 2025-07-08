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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Customize the program state: track local struct regions flagged as uninitialized.
// True indicates the structure may contain uninitialized (padding) bytes.
REGISTER_MAP_WITH_PROGRAMSTATE(UninitStructMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>,
                                          check::PostCall,
                                          check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Uninitialized Struct Leak")) {}

  // Callback: after a declaration statement is processed.
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;

  // Callback: after a function call is processed.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: before a function call is processed.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

/// checkPostStmt - When a local variable is declared, if it is a struct (record)
/// type and it is not explicitly initialized, mark its memory region as uninitialized.
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    // Only consider local variables.
    if (!VD->isLocalVarDecl())
      continue;
    // Only track struct/record types.
    if (!VD->getType()->isRecordType())
      continue;
    // If the variable has an initializer then we assume it was properly set.
    if (VD->hasInit())
      continue;

    // Create a temporary DeclRefExpr so we can retrieve its SVal.
    const ASTContext &Ctx = C.getASTContext();
    DeclRefExpr *DRE = new (Ctx) DeclRefExpr(const_cast<VarDecl*>(VD), false, VD->getType(), VK_LValue, DS->getBeginLoc());
    SVal Val = C.getSVal(DRE);
    const MemRegion *MR = Val.getAsRegion();
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;
    State = State->set<UninitStructMap>(MR, true);
  }
  C.addTransition(State);
}

/// checkPostCall - When a function call returns, check if it is a memset call that
/// zero-initializes a structure.  If so, update our state so that the corresponding
/// structure is marked as initialized.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;
  // Check if the call is to 'memset'.
  if (!ExprHasName(Origin, "memset", C))
    return;
  // Ensure there are at least three arguments.
  if (Call.getNumArgs() < 3)
    return;
  // Check that the second argument (value) is constant zero.
  const Expr *SecondArg = Call.getArgExpr(1);
  llvm::APSInt ZeroVal;
  if (!EvaluateExprToInt(ZeroVal, SecondArg, C))
    return;
  if (ZeroVal != 0)
    return;

  // Evaluate the size argument.
  const Expr *SizeExpr = Call.getArgExpr(2);
  llvm::APSInt SizeVal;
  if (!EvaluateExprToInt(SizeVal, SizeExpr, C))
    return;

  // Get the destination pointer (first argument) of memset.
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;
  const MemRegion *MR = getMemRegionFromExpr(DestExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Determine the expected size of the object being zeroed.
  QualType DestType = DestExpr->getType();
  // The destination type should be a pointer type.
  const PointerType *PT = DestType->getAs<PointerType>();
  if (!PT)
    return;
  QualType PointeeTy = PT->getPointeeType();
  // We are only interested if it points to a struct type.
  if (!PointeeTy->isRecordType())
    return;
  const ASTContext &Ctx = C.getASTContext();
  // Get the size (in characters/bytes) of the structure.
  CharUnits StructSize = Ctx.getTypeSizeInChars(PointeeTy);
  if (SizeVal.getExtValue() != (uint64_t)StructSize.getQuantity())
    return;

  // Mark the destination structure as initialized.
  State = State->set<UninitStructMap>(MR, false);
  C.addTransition(State);
}

/// checkPreCall - Before a function call that copies data to user space (for instance,
/// via 'nla_put' or 'nla_put_64bit'), check if the source structure is still uninitialized.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;
  // We're interested in calls that eventually copy a struct to user space.
  if (!(ExprHasName(Origin, "nla_put", C) || ExprHasName(Origin, "nla_put_64bit", C)))
    return;
  // For both functions, the source pointer argument is at index 3.
  unsigned PtrArgIdx = 3;
  if (Call.getNumArgs() <= PtrArgIdx)
    return;
  const Expr *DataExpr = Call.getArgExpr(PtrArgIdx);
  if (!DataExpr)
    return;
  const MemRegion *MR = getMemRegionFromExpr(DataExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  std::optional<bool> UninitFlag = State->get<UninitStructMap>(MR);
  if (UninitFlag.has_value() && UninitFlag.value()) {
    // Report a warning for copying an uninitialized structure.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report =
        std::make_unique<PathSensitiveBugReport>(*BT,
            "Local structure with padding not zero-initialized may leak uninitialized bytes", N);
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects local structures with padding that are not fully zero-initialized before copying to user space",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
