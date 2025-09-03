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
  std::ofstream logFile("/tmp/v8_checker_debug.log", std::ios::app);
  if (logFile.is_open()) {
    logFile << "[SAGenTestChecker] " << msg << std::endl;
    logFile.close();
  }
  // Also output to llvm::errs() for immediate visibility
  llvm::errs() << "[SAGenTestChecker DEBUG] " << msg << "\n";
}

namespace {

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;
   mutable int totalFunctionsAnalyzed = 0;
   mutable int totalForLoopsFound = 0;
   mutable int totalBugsFound = 0;

   public:
      SAGenTestChecker() : BT(new BugType(this, "For-loop pre-check dereference", "Memory safety")) {
        debugLog("SAGenTestChecker initialized");
      }

      ~SAGenTestChecker() {
        debugLog("SAGenTestChecker destroyed - Functions: " + std::to_string(totalFunctionsAnalyzed) + 
                 ", Loops: " + std::to_string(totalForLoopsFound) + 
                 ", Bugs: " + std::to_string(totalBugsFound));
      }

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Helpers
      const VarDecl *getLoopPtrFromCondition(const Expr *Cond) const;
      bool containsDerefOfVar(const Expr *E, const VarDecl *VD, const UnaryOperator *&DerefUO) const;
      bool containsDerefOfPreIncVar(const Expr *E, const VarDecl *VD, const UnaryOperator *&DerefUO) const;

      void analyzeForStmt(const ForStmt *FS, AnalysisManager &Mgr, BugReporter &BR, const std::string &funcName) const;
      void traverseStmt(const Stmt *S, AnalysisManager &Mgr, BugReporter &BR, const std::string &funcName) const;
};

static bool isRelOrNe(BinaryOperatorKind Op) {
  return Op == BO_LT || Op == BO_LE || Op == BO_GT || Op == BO_GE || Op == BO_NE;
}

const VarDecl *SAGenTestChecker::getLoopPtrFromCondition(const Expr *Cond) const {
  if (!Cond) {
    debugLog("  - Condition is null");
    return nullptr;
  }

  const Expr *E = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO) {
    debugLog("  - Condition is not a binary operator");
    return nullptr;
  }

  if (!isRelOrNe(BO->getOpcode())) {
    debugLog("  - Binary operator is not relational/ne");
    return nullptr;
  }

  auto GetPtrVar = [](const Expr *Operand) -> const VarDecl * {
    Operand = Operand ? Operand->IgnoreParenImpCasts() : nullptr;
    if (!Operand)
      return nullptr;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Operand)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (VD->getType()->isPointerType()) {
          debugLog("    Found pointer variable: " + VD->getNameAsString());
          return VD;
        }
      }
    }
    return nullptr;
  };

  if (const VarDecl *L = GetPtrVar(BO->getLHS()))
    return L;
  if (const VarDecl *R = GetPtrVar(BO->getRHS()))
    return R;

  debugLog("  - No pointer variable found in condition");
  return nullptr;
}

bool SAGenTestChecker::containsDerefOfVar(const Expr *E, const VarDecl *VD,
                                          const UnaryOperator *&DerefUO) const {
  if (!E || !VD)
    return false;

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (DRE->getDecl() == VD) {
          DerefUO = UO;
          debugLog("    Found dereference of " + VD->getNameAsString());
          return true;
        }
      }
    }
  }

  // Recurse into children
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child)) {
      if (containsDerefOfVar(CE, VD, DerefUO))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::containsDerefOfPreIncVar(const Expr *E, const VarDecl *VD,
                                                const UnaryOperator *&DerefUO) const {
  if (!E || !VD)
    return false;

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
      if (const auto *UO2 = dyn_cast<UnaryOperator>(Sub)) {
        if (UO2->getOpcode() == UO_PreInc) {
          const Expr *Inner = UO2->getSubExpr()->IgnoreParenCasts();
          if (const auto *DRE = dyn_cast<DeclRefExpr>(Inner)) {
            if (DRE->getDecl() == VD) {
              DerefUO = UO;
              debugLog("    Found dereference of pre-incremented " + VD->getNameAsString());
              return true;
            }
          }
        }
      }
    }
  }

  // Recurse into children
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child)) {
      if (containsDerefOfPreIncVar(CE, VD, DerefUO))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::analyzeForStmt(const ForStmt *FS, AnalysisManager &Mgr, BugReporter &BR, 
                                      const std::string &funcName) const {
  if (!FS)
    return;

  totalForLoopsFound++;
  debugLog("  Analyzing for-loop #" + std::to_string(totalForLoopsFound) + " in function: " + funcName);

  const Expr *Cond = FS->getCond();
  const VarDecl *PtrVD = getLoopPtrFromCondition(Cond);
  if (!PtrVD) {
    debugLog("  - No pointer variable in loop condition, skipping");
    return;
  }

  debugLog("  - Found pointer variable in condition: " + PtrVD->getNameAsString());

  // Check initializer
  const Stmt *Init = FS->getInit();
  if (Init) {
    debugLog("  - Checking initializer");
    const UnaryOperator *DerefUO = nullptr;

    if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
      for (const Decl *D : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(D)) {
          const Expr *InitE = VD->getInit();
          if (InitE && containsDerefOfVar(InitE, PtrVD, DerefUO)) {
            totalBugsFound++;
            debugLog("  *** BUG FOUND #" + std::to_string(totalBugsFound) + 
                    " in initializer: dereference before bound check");
            auto R = std::make_unique<BasicBugReport>(
                *BT,
                "Dereference in for-loop initializer occurs before bound check; possible out-of-bounds read.",
                DerefUO ? PathDiagnosticLocation::createBegin(DerefUO, BR.getSourceManager(), nullptr)
                        : PathDiagnosticLocation::createBegin(Init, BR.getSourceManager(), nullptr));
            if (DerefUO)
              R->addRange(DerefUO->getSourceRange());
            BR.emitReport(std::move(R));
          }
        }
      }
    } else if (const auto *IE = dyn_cast<Expr>(Init)) {
      if (containsDerefOfVar(IE, PtrVD, DerefUO)) {
        totalBugsFound++;
        debugLog("  *** BUG FOUND #" + std::to_string(totalBugsFound) + 
                " in initializer expr: dereference before bound check");
        auto R = std::make_unique<BasicBugReport>(
            *BT,
            "Dereference in for-loop initializer occurs before bound check; possible out-of-bounds read.",
            DerefUO ? PathDiagnosticLocation::createBegin(DerefUO, BR.getSourceManager(), nullptr)
                    : PathDiagnosticLocation::createBegin(IE, BR.getSourceManager(), nullptr));
        if (DerefUO)
          R->addRange(DerefUO->getSourceRange());
        BR.emitReport(std::move(R));
      }
    }
  }

  // Check increment
  const Expr *Inc = FS->getInc();
  if (Inc) {
    debugLog("  - Checking increment");
    const UnaryOperator *DerefUO = nullptr;
    if (containsDerefOfPreIncVar(Inc, PtrVD, DerefUO)) {
      totalBugsFound++;
      debugLog("  *** BUG FOUND #" + std::to_string(totalBugsFound) + 
              " in increment: dereference of pre-incremented iterator");
      auto R = std::make_unique<BasicBugReport>(
          *BT,
          "Dereference of pre-incremented iterator in for-loop increment occurs before bound check; possible out-of-bounds read.",
          DerefUO ? PathDiagnosticLocation::createBegin(DerefUO, BR.getSourceManager(), nullptr)
                  : PathDiagnosticLocation::createBegin(Inc, BR.getSourceManager(), nullptr));
      if (DerefUO)
        R->addRange(DerefUO->getSourceRange());
      BR.emitReport(std::move(R));
    }
  }
}

void SAGenTestChecker::traverseStmt(const Stmt *S, AnalysisManager &Mgr, BugReporter &BR, 
                                    const std::string &funcName) const {
  if (!S)
    return;

  if (const auto *FS = dyn_cast<ForStmt>(S))
    analyzeForStmt(FS, Mgr, BR, funcName);

  for (const Stmt *Child : S->children()) {
    if (Child)
      traverseStmt(Child, Mgr, BR, funcName);
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D)
    return;

  totalFunctionsAnalyzed++;
  
  std::string funcName = "unknown";
  if (const auto *FD = dyn_cast<FunctionDecl>(D)) {
    funcName = FD->getNameAsString();
  } else if (const auto *MD = dyn_cast<ObjCMethodDecl>(D)) {
    funcName = MD->getNameAsString();
  }
  
  debugLog("Analyzing function #" + std::to_string(totalFunctionsAnalyzed) + ": " + funcName);

  const Stmt *Body = D->getBody();
  if (!Body) {
    debugLog("  - No body found");
    return;
  }

  traverseStmt(Body, Mgr, BR, funcName);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  debugLog("=== Registering SAGenTestChecker ===");
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect dereference in for-loop init/increment before the loop bound check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;