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

#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states.
// InitPointerMap: records auto-cleanup pointer regions to a bool flag:
//         true => initialized to NULL, false => not initialized.
REGISTER_MAP_WITH_PROGRAMSTATE(InitPointerMap, const MemRegion *, bool)
// PtrAliasMap: track aliasing between pointer regions.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// A RecursiveASTVisitor to collect VarDecls inside a function body.
class VarDeclVisitor : public RecursiveASTVisitor<VarDeclVisitor> {
  const SourceManager &SM;
  const LangOptions &LangOpts;
  std::vector<const VarDecl *> &Results;

public:
  VarDeclVisitor(const SourceManager &SM, const LangOptions &LangOpts,
                 std::vector<const VarDecl *> &Results)
      : SM(SM), LangOpts(LangOpts), Results(Results) {}

  bool VisitVarDecl(VarDecl *VD) {
    // We only want pointer variables.
    if (!VD->getType()->isPointerType())
      return true;

    // Get the source text of the declaration.
    CharSourceRange R = CharSourceRange::getTokenRange(VD->getSourceRange());
    StringRef DeclText = Lexer::getSourceText(R, SM, LangOpts);
    // Check if the declaration contains the cleanup annotation "__free(kfree)"
    if (DeclText.contains("__free(kfree)"))
      Results.push_back(VD);
    return true;
  }
};

class SAGenTestChecker : public Checker< check::BeginFunction,
                                          check::Bind,
                                          check::EndFunction > {
   mutable std::unique_ptr<BugType> BT;
public:
   SAGenTestChecker() 
     : BT(new BugType(this, "Uninitialized auto-cleanup pointer",
                      "Memory Initialization")) {}

   // Callback: When a function analysis begins.
   void checkBeginFunction(CheckerContext &C) const {
     ProgramStateRef State = C.getState();
     // Get the current function declaration.
     // Use the location context to obtain the Decl.
     const Decl *D = C.getLocationContext()->getDecl();
     const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
     if (!FD || !FD->hasBody())
       return;

     // Use a RecursiveASTVisitor to collect VarDecls that are pointer types
     // and have the __free(kfree) annotation.
     std::vector<const VarDecl *> VarDecls;
     VarDeclVisitor Visitor(C.getSourceManager(), C.getLangOpts(), VarDecls);
     Visitor.TraverseStmt(FD->getBody());

     // For each auto-cleanup pointer variable, record its initialized status.
     for (const VarDecl *VD : VarDecls) {
       // Obtain the memory region for the variable.
       SVal V = C.getState()->getLValue(VD, C.getLocationContext());
       const MemRegion *MR = V.getAsRegion();
       if (!MR)
         continue;

       bool isInitializedToNull = false;
       if (VD->hasInit()) {
         // Try to evaluate the initializer to an integer constant.
         llvm::APSInt EvalRes;
         if (EvaluateExprToInt(EvalRes, VD->getInit(), C)) {
           // Check if the evaluated value equals 0.
           if (EvalRes == 0)
             isInitializedToNull = true;
         }
       }
       // If there is no initializer or it is not explicitly zero,
       // mark it as not safely initialized.
       State = State->set<InitPointerMap>(MR, isInitializedToNull);
     }
     C.addTransition(State);
   }

   // Callback: When pointer assignments occur.
   void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
     ProgramStateRef State = C.getState();

     const MemRegion *LHSReg = Loc.getAsRegion();
     const MemRegion *RHSReg = Val.getAsRegion();
     if (!LHSReg || !RHSReg)
       return;

     // Propagate initialization status.
     const bool *LHSInit = State->get<InitPointerMap>(LHSReg);
     const bool *RHSInit = State->get<InitPointerMap>(RHSReg);
     // If either side is marked as initialized (true), then propagate that.
     if ((LHSInit && *LHSInit) || (RHSInit && *RHSInit)) {
       State = State->set<InitPointerMap>(LHSReg, true);
       State = State->set<InitPointerMap>(RHSReg, true);
     }
     // Record an alias relation between the two.
     State = State->set<PtrAliasMap>(LHSReg, RHSReg);
     State = State->set<PtrAliasMap>(RHSReg, LHSReg);
     C.addTransition(State);
   }

   // Callback: At the end of function, check all tracked auto-cleanup pointers.
   void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
     ProgramStateRef State = C.getState();
     // Retrieve the entire InitPointerMap.
     auto Map = State->get<InitPointerMap>();
     // Iterate over the map entries.
     for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
       // If the pointer is not safely initialized (i.e. not set to NULL).
       if (!I->second) {
         const MemRegion *MR = I->first;
         // Generate a non-fatal error node.
         ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
         if (!ErrNode)
           continue;
         // Create a bug report.
         auto Report = std::make_unique<PathSensitiveBugReport>(
             *BT, "Auto-cleaned pointer not explicitly initialized to NULL", ErrNode);
         // Optionally, add the region's source range (if available).
         if (const VarRegion *VR = dyn_cast<VarRegion>(MR))
           Report->addRange(VR->getDecl()->getSourceRange());
         C.emitReport(std::move(Report));
       }
     }
   }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Warns for auto-cleanup pointers (marked __free(kfree)) not initialized to NULL", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
