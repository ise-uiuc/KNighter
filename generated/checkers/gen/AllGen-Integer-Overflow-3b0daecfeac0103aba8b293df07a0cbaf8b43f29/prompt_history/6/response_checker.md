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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track variables that currently hold a size computed as (count * sizeof(...))
REGISTER_MAP_WITH_PROGRAMSTATE(SizeMulMap, const MemRegion*, bool)

namespace {
class SAGenTestChecker : public Checker<
    check::PreCall,
    check::Bind
  > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Size multiplication passed to allocator", "Memory Allocation")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isMulBySizeof(const Expr *E, const Expr *&CountExpr);
      static bool isSizeofExpr(const Expr *E);
      static bool matchCallName(const CallEvent &Call, CheckerContext &C, StringRef Name);
      static bool isAllocLike(const CallEvent &Call, CheckerContext &C, StringRef &NameOut);
      static StringRef getArrayAllocatorSuggestion(StringRef CalleeName);
};

// Check if expression is a sizeof(...) (after stripping parens/imp-casts)
bool SAGenTestChecker::isSizeofExpr(const Expr *E) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    return U->getKind() == UETT_SizeOf;
  }
  return false;
}

// Check if E is a multiplication where one side is sizeof(...).
// If true, CountExpr is set to the non-sizeof operand.
bool SAGenTestChecker::isMulBySizeof(const Expr *E, const Expr *&CountExpr) {
  CountExpr = nullptr;
  if (!E) return false;
  E = E->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO) return false;
  if (BO->getOpcode() != BO_Mul) return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  if (isSizeofExpr(LHS)) {
    CountExpr = RHS;
    return true;
  }
  if (isSizeofExpr(RHS)) {
    CountExpr = LHS;
    return true;
  }
  return false;
}

bool SAGenTestChecker::matchCallName(const CallEvent &Call, CheckerContext &C, StringRef Name) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;
  return ExprHasName(OE, Name, C);
}

// Return true if this is one of the kmalloc/kzalloc family that take a byte size.
// NameOut will be set to the matched callee name.
bool SAGenTestChecker::isAllocLike(const CallEvent &Call, CheckerContext &C, StringRef &NameOut) {
  static const char *Targets[] = {
    "kmalloc", "__kmalloc", "kzalloc", "kvmalloc", "kvzalloc",
    "devm_kmalloc", "devm_kzalloc"
  };
  for (const char *T : Targets) {
    if (matchCallName(Call, C, T)) {
      NameOut = T;
      return true;
    }
  }
  return false;
}

// Suggest an array allocator for the given allocator name.
StringRef SAGenTestChecker::getArrayAllocatorSuggestion(StringRef CalleeName) {
  if (CalleeName.equals("kzalloc")) return "kcalloc";
  if (CalleeName.equals("devm_kzalloc")) return "devm_kcalloc";
  if (CalleeName.equals("kmalloc") || CalleeName.equals("__kmalloc")) return "kmalloc_array";
  if (CalleeName.equals("devm_kmalloc")) return "devm_kmalloc_array";
  if (CalleeName.equals("kvmalloc")) return "kvmalloc_array";
  if (CalleeName.equals("kvzalloc")) return "kvcalloc";
  // Default generic suggestion
  return "kcalloc/kmalloc_array";
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  StringRef CalleeName;
  if (!isAllocLike(Call, C, CalleeName))
    return;

  // All targeted allocators take size as the first argument.
  if (Call.getNumArgs() == 0)
    return;

  const Expr *SizeArgE = Call.getArgExpr(0);
  if (!SizeArgE)
    return;

  const Expr *CountExpr = nullptr;
  bool ShouldReport = false;

  // 1) Direct pattern: multiplication where one side is sizeof(...)
  if (isMulBySizeof(SizeArgE, CountExpr)) {
    ShouldReport = true;
  } else {
    // 2) Indirect via variable holding sizeof(...) * count
    const Expr *E = SizeArgE->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      ProgramStateRef State = C.getState();
      const MemRegion *MR = getMemRegionFromExpr(DRE, C);
      if (MR) {
        MR = MR->getBaseRegion();
        if (MR) {
          if (const bool *IsMul = State->get<SizeMulMap>(MR)) {
            if (*IsMul)
              ShouldReport = true;
          }
        }
      }
    }
  }

  if (!ShouldReport)
    return;

  // Report: Recommend array allocator to avoid overflow.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
  StringRef Suggest = getArrayAllocatorSuggestion(CalleeName);
  Msg.append("Use array allocator to avoid overflow; prefer ");
  Msg.append(Suggest);

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg.str(), N);
  R->addRange(SizeArgE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  // Only track simple variables (avoid binding to arbitrary memory like *p, p[i], etc.)
  if (!isa<VarRegion>(LHSReg))
    return;

  // Find an RHS expression from the statement context
  const Expr *RHS = nullptr;

  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      RHS = BO->getRHS();
  }
  if (!RHS) {
    if (const auto *DS = dyn_cast_or_null<DeclStmt>(S)) {
      for (const Decl *D : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(D)) {
          if (const Expr *Init = VD->getInit())
            RHS = Init;
        }
      }
    }
  }
  if (!RHS) {
    if (const auto *BO = findSpecificTypeInParents<BinaryOperator>(S, C)) {
      if (BO->isAssignmentOp())
        RHS = BO->getRHS();
    }
  }
  if (!RHS) {
    if (const auto *DS = findSpecificTypeInParents<DeclStmt>(S, C)) {
      for (const Decl *D : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(D)) {
          if (const Expr *Init = VD->getInit())
            RHS = Init;
        }
      }
    }
  }

  if (!RHS) {
    // No usable RHS expression found, clear any previous mark
    State = State->remove<SizeMulMap>(LHSReg);
    C.addTransition(State);
    return;
  }

  const Expr *CountExpr = nullptr;
  if (isMulBySizeof(RHS, CountExpr)) {
    State = State->set<SizeMulMap>(LHSReg, true);
  } else {
    State = State->remove<SizeMulMap>(LHSReg);
  }
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects size multiplication passed to kmalloc/kzalloc family; suggest kcalloc/kmalloc_array",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
