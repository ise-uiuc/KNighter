#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
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

// Additional include for std::optional if needed in the future
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states: register a map to track partially initialized "tc_skbmod" structures.
// The mapping stores a pointer to the MemRegion for the variable and a flag: true means partially uninitialized.
REGISTER_MAP_WITH_PROGRAMSTATE(UninitStructMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>, check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker()
    // In newer Clang versions, BugType's constructor just takes the bug name and category.
    : BT(new BugType("Partial Initialization Leak", "Kernel Info-leak")) {}

  // Callback for declaration statements: check for partially-initialized tc_skbmod structures.
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  
  // Callback for memset calls: mark the structure as fully initialized.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  
  // Callback for copy-to-user calls: report if a partially-initialized structure is used.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report bug.
  void reportPartialInitBug(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const;
};

/// checkPostStmt: Process declaration statements.
/// Look for VarDecls whose type contains "tc_skbmod" and which are initialized via a compound literal
/// with fewer initializer elements than the total number of fields in the record.
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
      QualType VT = VD->getType();
      if (!VT->isRecordType())
        continue;
      // Check if the record type's name contains "tc_skbmod"
      const RecordType *RT = VT->getAs<RecordType>();
      if (!RT)
        continue;
      RecordDecl *RD = RT->getDecl();
      if (!RD)
        continue;
      std::string TypeName = RD->getNameAsString();
      if (TypeName.find("tc_skbmod") == std::string::npos)
        continue;
      
      // Check if a compound initializer is used.
      if (const InitListExpr *ILE = dyn_cast_or_null<InitListExpr>(VD->getInit())) {
        // Heuristic: count the initializer elements vs. the number of fields.
        unsigned numInits = ILE->getNumInits();
        // Count the fields in the record.
        unsigned numFields = 0;
        for (const FieldDecl *Field : RD->fields())
          ++numFields;
        
        if (numInits < numFields) {
          // We have a partial initializer.
          // Obtain the memory region for the variable.
          // Create a DeclRefExpr for the VarDecl.
          DeclarationNameInfo DNI(VD, VD->getLocation());
          Expr *FakeDRE = new (C.getASTContext()) DeclRefExpr(const_cast<VarDecl*>(VD),
                                                              DNI,
                                                              VD->getType(),
                                                              VK_LValue);
          const MemRegion *MR = getMemRegionFromExpr(FakeDRE, C);
          if (!MR)
            continue;
          MR = MR->getBaseRegion();
          if (!MR)
            continue;
          State = State->set<UninitStructMap>(MR, true);
          C.addTransition(State);
        }
      }
    }
  }
}

/// checkPostCall: Handle calls to memset.
/// If memset is called on a destination that is in our UninitStructMap, mark it as fully initialized (false).
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Check if the called function is "memset"
  if (!ExprHasName(OriginExpr, "memset", C))
    return;
  
  // For memset, the first argument is the destination buffer.
  if (Call.getNumArgs() < 1)
    return;
  SVal DestVal = Call.getArgSVal(0);
  const MemRegion *MR = DestVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // If the region is marked as uninitialized, update it to false.
  if (const bool *Flag = State->get<UninitStructMap>(MR)) {
    if (*Flag == true) {
      State = State->set<UninitStructMap>(MR, false);
      C.addTransition(State);
    }
  }
}

/// checkPreCall: Before a call that copies memory to user space is executed,
/// check if a partially-initialized structure is being used.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Check for functions that copy memory to user space.
  // We consider functions with names "nla_put" and "nla_put_64bit" as examples.
  if (!(ExprHasName(OriginExpr, "nla_put", C) ||
        ExprHasName(OriginExpr, "nla_put_64bit", C)))
    return;
  
  // Heuristically, these functions have the structure pointer as an argument.
  // For nla_put, the 4th argument (index 3) is the source buffer.
  if (Call.getNumArgs() <= 3)
    return;
  
  SVal BufVal = Call.getArgSVal(3);
  const MemRegion *MR = BufVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  ProgramStateRef State = C.getState();
  if (const bool *Flag = State->get<UninitStructMap>(MR)) {
    if (*Flag == true) {
      // Report bug: structure is partially initialized.
      reportPartialInitBug(MR, Call, C);
    }
  }
}

/// Helper function to report a bug about using a partially initialized structure.
void SAGenTestChecker::reportPartialInitBug(const MemRegion *MR,
                                            const CallEvent &Call,
                                            CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  // Use a PathSensitiveBugReport constructor that takes a BugType, a short descriptive message,
  // and the error node.
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Partial initialization of 'tc_skbmod' structure may leak uninitialized memory", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects partial initialization of 'tc_skbmod' structure that can lead to kernel infoleak", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
