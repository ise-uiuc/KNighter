## Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

## Instruction

The following checker fails to compile, and your task is to resolve the compilation error based on the provided error messages.

Here are some potential ways to fix the issue:

1. Use the correct API: The current API may not exist, or the class has no such member. Replace it with an appropriate one.

2. Use correct arguments: Ensure the arguments passed to the API have the correct types and the correct number.

3. Change the variable types: Adjust the types of some variables based on the error messages.

4. Be careful if you want to include a header file. Please make sure the header file exists. For instance "fatal error: clang/StaticAnalyzer/Core/PathDiagnostic.h: No such file or directory".

**The version of Clang environment is Clang-18. You should consider the API compatibility.**

**Please only repair the failed parts and keep the original semantics.**
**Please return the whole checker code after fixing the compilation error.**

## Suggestions

1. Please only use two types of bug reports:
  - BasicBugReport (const BugType &bt, StringRef desc, PathDiagnosticLocation l)
  - PathSensitiveBugReport (const BugType &bt, StringRef desc, const ExplodedNode *errorNode)
  - PathSensitiveBugReport (const BugType &bt, StringRef shortDesc, StringRef desc, const ExplodedNode *errorNode)

## Example

- Error Line: 48 |   Optional<DefinedOrUnknownSVal> SizeSVal;

  - Error Messages: ‘Optional’ was not declared in this scope; did you mean ‘clang::ObjCImplementationControl::Optional’?

  - Fix: Replace 'Optional<DefinedOrUnknownSVal>' with 'std::optional<DefinedOrUnknownSVal>', and include the appropriate header.

- Error Line: 113 |     const MemRegion *MR = Entry.first;

    - Error Messages: unused variable ‘MR’ [-Wunused-variable]

    - Fix: Remove the variable 'MR' if it is not used.

## Checker

```cpp
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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are required.

namespace {

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unconditional read before guard", "Concurrency")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  // Helpers to scan blocks and statements
  void scanStmt(const Stmt *S, const Decl *D, AnalysisManager &Mgr,
                BugReporter &BR) const;

  void scanCompound(const CompoundStmt *CS, const Decl *D, AnalysisManager &Mgr,
                    BugReporter &BR) const;

  // Helpers to classify statements
  static bool getAssignmentFromDeclStmt(const Stmt *S, const VarDecl *&LHSVD,
                                        const Expr *&RHS);
  static bool getAssignmentFromBinOp(const Stmt *S, const VarDecl *&LHSVD,
                                     const Expr *&RHS);

  // Pattern recognizers
  static bool isSuspiciousSharedRead(const Expr *RHS, const Expr *&Spot);
  static bool matchWorkDataBitsCall(const Expr *E, const Expr *&Spot);
  static bool matchWorkArrowData(const Expr *E, const Expr *&Spot);

  // Condition analysis
  static bool condMentionsVar(const Expr *Cond, const VarDecl *VD);
  static bool condMentionsName(const Expr *Cond, StringRef Name);
};

bool SAGenTestChecker::getAssignmentFromDeclStmt(const Stmt *S,
                                                 const VarDecl *&LHSVD,
                                                 const Expr *&RHS) {
  LHSVD = nullptr;
  RHS = nullptr;
  const auto *DS = dyn_cast<DeclStmt>(S);
  if (!DS || !DS->isSingleDecl())
    return false;

  const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
  if (!VD)
    return false;

  if (!VD->hasInit())
    return false;

  // Prefer local or function scope vars
  if (!VD->hasLocalStorage())
    return false;

  LHSVD = VD;
  RHS = VD->getInit();
  return true;
}

bool SAGenTestChecker::getAssignmentFromBinOp(const Stmt *S,
                                              const VarDecl *&LHSVD,
                                              const Expr *&RHS) {
  LHSVD = nullptr;
  RHS = nullptr;

  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(LHS);
  if (!DRE)
    return false;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return false;

  if (!VD->hasLocalStorage())
    return false;

  LHSVD = VD;
  RHS = BO->getRHS();
  return true;
}

static const FunctionDecl *getDirectCallee(const CallExpr *CE) {
  if (const FunctionDecl *FD = CE->getDirectCallee())
    return FD;

  const Expr *CalleeE = CE->getCallee()->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(CalleeE))
    return dyn_cast<FunctionDecl>(DRE->getDecl());
  return nullptr;
}

bool SAGenTestChecker::matchWorkDataBitsCall(const Expr *E,
                                             const Expr *&Spot) {
  Spot = nullptr;
  const Expr *X = E ? E->IgnoreParenCasts() : nullptr;
  if (!X)
    return false;

  // Allow unary '*' on top of the call
  if (const auto *UO = dyn_cast<UnaryOperator>(X)) {
    if (UO->getOpcode() == UO_Deref)
      X = UO->getSubExpr()->IgnoreParenImpCasts();
  }

  const CallExpr *CE = dyn_cast<CallExpr>(X);
  if (!CE) {
    // Try to locate a CallExpr somewhere inside the expression tree
    CE = findSpecificTypeInChildren<CallExpr>(E);
    if (!CE)
      return false;
  }

  const FunctionDecl *FD = getDirectCallee(CE);
  if (!FD)
    return false;

  if (FD->getIdentifier() && FD->getName() == "work_data_bits") {
    // Also ensure the first argument is 'work' to be precise
    if (CE->getNumArgs() >= 1) {
      const Expr *Arg0 = CE->getArg(0)->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Arg0)) {
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (VD->getName() == "work") {
            Spot = CE;
            return true;
          }
        }
      }
    }
  }
  return false;
}

bool SAGenTestChecker::matchWorkArrowData(const Expr *E, const Expr *&Spot) {
  Spot = nullptr;
  const Expr *X = E ? E->IgnoreParenImpCasts() : nullptr;
  if (!X)
    return false;

  const auto *ME = dyn_cast<MemberExpr>(X);
  if (!ME)
    return false;

  if (!ME->isArrow())
    return false;

  const ValueDecl *MD = ME->getMemberDecl();
  if (!MD || !MD->getIdentifier() || MD->getName() != "data")
    return false;

  const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE)
    return false;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return false;

  if (VD->getName() != "work")
    return false;

  Spot = ME;
  return true;
}

bool SAGenTestChecker::isSuspiciousSharedRead(const Expr *RHS,
                                              const Expr *&Spot) {
  Spot = nullptr;
  if (!RHS)
    return false;

  // Pattern A: *work_data_bits(work)
  if (matchWorkDataBitsCall(RHS, Spot))
    return true;

  // Pattern B: work->data
  if (matchWorkArrowData(RHS, Spot))
    return true;

  return false;
}

static bool walkContainsVar(const Stmt *S, const VarDecl *VD) {
  if (!S || !VD)
    return false;

  for (const Stmt *Child : S->children()) {
    if (!Child)
      continue;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Child)) {
      if (DRE->getDecl() == VD)
        return true;
    }
    if (walkContainsVar(Child, VD))
      return true;
  }
  return false;
}

static bool walkContainsName(const Stmt *S, StringRef Name) {
  if (!S)
    return false;

  for (const Stmt *Child : S->children()) {
    if (!Child)
      continue;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Child)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (VD->getName() == Name)
          return true;
      }
    }
    if (walkContainsName(Child, Name))
      return true;
  }
  return false;
}

bool SAGenTestChecker::condMentionsVar(const Expr *Cond, const VarDecl *VD) {
  return walkContainsVar(Cond, VD);
}

bool SAGenTestChecker::condMentionsName(const Expr *Cond, StringRef Name) {
  return walkContainsName(Cond, Name);
}

void SAGenTestChecker::scanCompound(const CompoundStmt *CS, const Decl *D,
                                    AnalysisManager &Mgr,
                                    BugReporter &BR) const {
  if (!CS)
    return;

  // Examine adjacent pairs of statements
  const AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(D);

  auto It = CS->body_begin();
  auto End = CS->body_end();
  if (It == End)
    return;

  for (; It != End; ++It) {
    const Stmt *S1 = *It;
    auto It2 = It;
    ++It2;
    if (It2 == End)
      break;
    const Stmt *S2 = *It2;

    const VarDecl *LHSVD = nullptr;
    const Expr *RHS = nullptr;

    bool IsAssign = getAssignmentFromDeclStmt(S1, LHSVD, RHS) ||
                    getAssignmentFromBinOp(S1, LHSVD, RHS);

    if (!IsAssign || !LHSVD || !RHS)
      continue;

    const auto *IfS = dyn_cast<IfStmt>(S2);
    if (!IfS)
      continue;

    const Expr *Cond = IfS->getCond();
    if (!Cond)
      continue;

    // Check that RHS is the suspicious shared-field read
    const Expr *Spot = nullptr;
    if (!isSuspiciousSharedRead(RHS, Spot))
      continue;

    // Check that condition mentions both the guard and the assigned variable
    if (!condMentionsName(Cond, "from_cancel"))
      continue;
    if (!condMentionsVar(Cond, LHSVD))
      continue;

    // Report a bug
    if (!Spot)
      Spot = RHS;

    PathDiagnosticLocation Loc =
        PathDiagnosticLocation::createBegin(Spot, BR.getSourceManager(), ADC);

    auto R = std::make_unique<BasicBugReport>(
        *BT,
        "Unconditional read of shared field before checking guard; move the "
        "read under the 'from_cancel' check.",
        Loc, Spot->getSourceRange());
    BR.emitReport(std::move(R));
  }

  // Recurse into children to find nested compound statements
  for (const Stmt *Child : CS->body()) {
    scanStmt(Child, D, Mgr, BR);
  }
}

void SAGenTestChecker::scanStmt(const Stmt *S, const Decl *D,
                                AnalysisManager &Mgr, BugReporter &BR) const {
  if (!S)
    return;

  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    scanCompound(CS, D, Mgr, BR);
    return;
  }

  // Recurse to find nested compound statements
  for (const Stmt *Child : S->children()) {
    scanStmt(Child, D, Mgr, BR);
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  scanStmt(Body, D, Mgr, BR);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unconditional read of shared field before guard (e.g., read of work->data or *work_data_bits(work) before checking from_cancel)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 317 |         PathDiagnosticLocation::createBegin(Spot, BR.getSourceManager(), ADC);

	- Error Messages: invalid conversion from ‘const clang::AnalysisDeclContext*’ to ‘clang::AnalysisDeclContext*’ [-fpermissive]

- Error Line: 962 |     { return unique_ptr<_Tp>(new _Tp(std::forward<_Args>(__args)...)); }

	- Error Messages: no matching function for call to ‘clang::ento::BasicBugReport::BasicBugReport(clang::ento::BugType&, const char [103], clang::ento::PathDiagnosticLocation&, clang::SourceRange)’



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
