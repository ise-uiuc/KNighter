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
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.
 // If necessary

namespace {

static bool isPinctrlMapRecord(QualType QT) {
  if (const auto *RT = QT->getAs<RecordType>()) {
    const RecordDecl *RD = RT->getDecl();
    if (!RD)
      return false;
    IdentifierInfo *II = RD->getIdentifier();
    if (!II)
      return false;
    return II->getName() == "pinctrl_map";
  }
  return false;
}

static bool isPinctrlMapPtr(QualType QT) {
  if (const auto *PT = QT->getAs<PointerType>()) {
    return isPinctrlMapRecord(PT->getPointeeType());
  }
  return false;
}

static bool isPinctrlMapPtrPtr(QualType QT) {
  if (const auto *PTOuter = QT->getAs<PointerType>()) {
    QualType Middle = PTOuter->getPointeeType();
    if (const auto *PTInner = Middle->getAs<PointerType>()) {
      return isPinctrlMapRecord(PTInner->getPointeeType());
    }
  }
  return false;
}

static const Expr *ignoreCastsAndParens(const Expr *E) {
  if (!E) return nullptr;
  return E->IgnoreParenImpCasts();
}

static const Expr *ignoreCastsParensAndAddrOf(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_AddrOf)
      return UO->getSubExpr()->IgnoreParenImpCasts();
  }
  return E;
}

static const FunctionDecl *getFunctionFromExpr(const Expr *E) {
  E = ignoreCastsParensAndAddrOf(E);
  if (!E) return nullptr;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<FunctionDecl>(DRE->getDecl());
  }
  return nullptr;
}

static bool isManualFreeName(StringRef Name) {
  return Name == "pinconf_generic_dt_free_map" || Name == "pinctrl_utils_free_map";
}

static bool isDevmAllocatorName(StringRef Name) {
  return Name == "devm_kcalloc" ||
         Name == "devm_kmalloc" ||
         Name == "devm_kmalloc_array" ||
         Name == "devm_kzalloc" ||
         Name == "devm_kmemdup" ||
         Name == "devm_krealloc";
}

static const CallExpr *getDirectCall(const Expr *E) {
  E = ignoreCastsAndParens(E);
  return dyn_cast_or_null<CallExpr>(E);
}

class SAGenTestChecker : public Checker<check::ASTDecl<VarDecl>,
                                        check::ASTDecl<FunctionDecl>,
                                        check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   // Functions wired as .dt_node_to_map in a struct that also sets .dt_free_map
   // to a manual-free helper.
   mutable llvm::SmallPtrSet<const FunctionDecl*, 32> DangerousDtNodeToMapFns;

   // Track which functions we've already scanned to avoid duplicate reports.
   mutable llvm::SmallPtrSet<const FunctionDecl*, 32> ScannedFns;

   // Track function definitions we've seen (may be scanned later when we
   // discover the struct wiring).
   mutable llvm::SmallPtrSet<const FunctionDecl*, 64> SeenFunctionDefs;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free: devm-managed map with dt_free_map", "Memory Management")) {}

      void checkASTDecl(const VarDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
      void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      const ParmVarDecl *findMapParam(const FunctionDecl *FD) const;
      void scanFunctionForBug(const FunctionDecl *FD, AnalysisManager &Mgr, BugReporter &BR) const;

      // Helper to add to Dangerous set and try immediate scanning if body known.
      void markDangerousAndMaybeScan(const FunctionDecl *FD, AnalysisManager &Mgr, BugReporter &BR) const;
};

class OpsInitVisitor : public RecursiveASTVisitor<OpsInitVisitor> {
  const ASTContext &Ctx;
public:
  const FunctionDecl *NodeToMapFn = nullptr;
  bool HasManualFree = false;

  explicit OpsInitVisitor(const ASTContext &Ctx) : Ctx(Ctx) {}

  bool VisitDesignatedInitExpr(DesignatedInitExpr *DIE) {
    // Check each designator
    for (unsigned i = 0, e = DIE->getNumDesignators(); i != e; ++i) {
      const DesignatedInitExpr::Designator &Des = DIE->getDesignator(i);
      if (!Des.isFieldDesignator())
        continue;

      IdentifierInfo *II = Des.getFieldName();
      if (!II)
        continue;

      StringRef FieldName = II->getName();
      const Expr *Init = DIE->getInit();
      if (!Init)
        continue;

      if (FieldName == "dt_node_to_map") {
        const FunctionDecl *FD = getFunctionFromExpr(Init);
        if (FD)
          NodeToMapFn = FD;
      } else if (FieldName == "dt_free_map") {
        const FunctionDecl *FD = getFunctionFromExpr(Init);
        if (FD) {
          IdentifierInfo *FII = FD->getIdentifier();
          if (FII && isManualFreeName(FII->getName()))
            HasManualFree = true;
        } else {
          // Fallback: try to match by text is not available, so ignore.
        }
      }
    }
    return true;
  }
};

class DevmMapBodyVisitor : public RecursiveASTVisitor<DevmMapBodyVisitor> {
public:
  const ParmVarDecl *MapParam = nullptr;
  ASTContext &Ctx;

  bool Found = false;
  const CallExpr *BadCallSite = nullptr;        // devm_* call to anchor report
  const BinaryOperator *BadAssignSite = nullptr; // fallback anchor

  // Track local variables of type struct pinctrl_map* that are assigned from devm_*.
  llvm::SmallPtrSet<const VarDecl*, 16> DevmVars;
  llvm::DenseMap<const VarDecl*, const CallExpr*> DevmVarToCall;

  // RHS vars used in *map = var assignments to resolve after traversal if needed.
  llvm::SmallVector<const VarDecl*, 8> PendingRHSVarsInMapAssign;

  explicit DevmMapBodyVisitor(const ParmVarDecl *MP, ASTContext &C) : MapParam(MP), Ctx(C) {}

  bool VisitDeclStmt(DeclStmt *DS) {
    if (Found) return true;
    for (Decl *D : DS->decls()) {
      if (auto *VD = dyn_cast<VarDecl>(D)) {
        QualType T = VD->getType();
        if (!isPinctrlMapPtr(T))
          continue;

        const Expr *Init = VD->getInit();
        if (!Init) continue;
        const CallExpr *CE = getDirectCall(Init);
        if (!CE) continue;
        if (const FunctionDecl *Callee = CE->getDirectCallee()) {
          IdentifierInfo *II = Callee->getIdentifier();
          if (II && isDevmAllocatorName(II->getName())) {
            DevmVars.insert(VD);
            DevmVarToCall[VD] = CE;
          }
        }
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (Found) return true;
    if (BO->getOpcode() != BO_Assign)
      return true;

    const Expr *LHS = ignoreCastsAndParens(BO->getLHS());
    const Expr *RHS = BO->getRHS();

    // Case: var = devm_*(...)
    if (const auto *LHS_DRE = dyn_cast<DeclRefExpr>(LHS)) {
      const VarDecl *VD = dyn_cast<VarDecl>(LHS_DRE->getDecl());
      if (VD && isPinctrlMapPtr(VD->getType())) {
        if (const CallExpr *CE = getDirectCall(RHS)) {
          if (const FunctionDecl *Callee = CE->getDirectCallee()) {
            if (IdentifierInfo *II = Callee->getIdentifier()) {
              if (isDevmAllocatorName(II->getName())) {
                DevmVars.insert(VD);
                DevmVarToCall[VD] = CE;
              }
            }
          }
        }
      }
    }

    // Case: *map = ...
    if (const auto *UO = dyn_cast<UnaryOperator>(LHS)) {
      if (UO->getOpcode() == UO_Deref) {
        const Expr *Sub = ignoreCastsAndParens(UO->getSubExpr());
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
          if (DRE->getDecl() == MapParam) {
            // RHS direct devm_* call
            if (const CallExpr *CE = getDirectCall(RHS)) {
              if (const FunctionDecl *Callee = CE->getDirectCallee()) {
                if (IdentifierInfo *II = Callee->getIdentifier()) {
                  if (isDevmAllocatorName(II->getName())) {
                    Found = true;
                    BadCallSite = CE;
                    BadAssignSite = BO;
                    return true;
                  }
                }
              }
            }
            // RHS is a variable that might be from devm_* earlier
            const Expr *R = ignoreCastsAndParens(RHS);
            if (const auto *RHS_DRE = dyn_cast<DeclRefExpr>(R)) {
              if (const VarDecl *RVD = dyn_cast<VarDecl>(RHS_DRE->getDecl())) {
                PendingRHSVarsInMapAssign.push_back(RVD);
              }
            }
            BadAssignSite = BO; // remember as fallback anchor
          }
        }
      }
    }

    return true;
  }

  void finalize() {
    if (Found) return;
    // Resolve pending RHS vars
    for (const VarDecl *VD : PendingRHSVarsInMapAssign) {
      if (DevmVars.contains(VD)) {
        Found = true;
        auto It = DevmVarToCall.find(VD);
        if (It != DevmVarToCall.end())
          BadCallSite = It->second;
        break;
      }
    }
  }
};

const ParmVarDecl *SAGenTestChecker::findMapParam(const FunctionDecl *FD) const {
  for (const ParmVarDecl *P : FD->parameters()) {
    if (isPinctrlMapPtrPtr(P->getType()))
      return P;
  }
  return nullptr;
}

void SAGenTestChecker::scanFunctionForBug(const FunctionDecl *FD, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!FD || ScannedFns.contains(FD))
    return;
  if (!FD->doesThisDeclarationHaveABody())
    return;

  const ParmVarDecl *MapParam = findMapParam(FD);
  if (!MapParam)
    return;

  Stmt *Body = const_cast<Stmt*>(FD->getBody());
  if (!Body)
    return;

  DevmMapBodyVisitor V(MapParam, Mgr.getASTContext());
  V.TraverseStmt(Body);
  V.finalize();

  if (V.Found) {
    const Stmt *Anchor = V.BadCallSite ? static_cast<const Stmt*>(V.BadCallSite)
                                       : static_cast<const Stmt*>(V.BadAssignSite ? V.BadAssignSite : Body);
    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(
        Anchor, BR.getSourceManager(), Mgr.getAnalysisDeclContext(FD));
    auto R = std::make_unique<BasicBugReport>(
        *BT, "devm_* allocation for pinctrl map mixed with dt_free_map causes double free", Loc);
    if (V.BadCallSite)
      R->addRange(V.BadCallSite->getSourceRange());
    BR.emitReport(std::move(R));
  }

  ScannedFns.insert(FD);
}

void SAGenTestChecker::markDangerousAndMaybeScan(const FunctionDecl *FD, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!FD)
    return;
  DangerousDtNodeToMapFns.insert(FD);
  // If we've already seen the body, or even if not, try scanning now.
  if (FD->doesThisDeclarationHaveABody())
    scanFunctionForBug(FD, Mgr, BR);
}

void SAGenTestChecker::checkASTDecl(const VarDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D)
    return;
  const Expr *Init = D->getInit();
  if (!Init)
    return;

  OpsInitVisitor V(Mgr.getASTContext());
  V.TraverseStmt(const_cast<Expr*>(Init));

  if (V.NodeToMapFn && V.HasManualFree) {
    markDangerousAndMaybeScan(V.NodeToMapFn, Mgr, BR);
  }
}

void SAGenTestChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D)
    return;
  if (!D->doesThisDeclarationHaveABody())
    return;

  SeenFunctionDefs.insert(D);

  // If we already know it's dangerous, scan immediately.
  if (DangerousDtNodeToMapFns.contains(D))
    scanFunctionForBug(D, Mgr, BR);
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  // If it's marked dangerous, scan; otherwise, it may be discovered later
  // when the struct variable with .dt_free_map is encountered.
  if (DangerousDtNodeToMapFns.contains(FD))
    scanFunctionForBug(FD, Mgr, BR);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects devm_* allocation for pinctrl map when dt_free_map is used, causing double free",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
