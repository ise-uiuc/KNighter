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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states

namespace {
class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Wrong NULL check after allocation", "Logic error")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      static const Expr *extractCheckedExprForNull(const Expr *CondE, CheckerContext &C);
      static bool isNullLiteral(const Expr *E, ASTContext &ACtx);
      static std::string getExprText(const Expr *E, CheckerContext &C);
      static bool isAllocLikeCall(const CallExpr *CE, CheckerContext &C);
};

static std::string getCalleeNameFromCall(const CallExpr *CE) {
  if (!CE) return {};
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (const IdentifierInfo *II = FD->getIdentifier())
      return II->getName().str();
  }
  return {};
}

std::string SAGenTestChecker::getExprText(const Expr *E, CheckerContext &C) {
  if (!E) return "";
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  return Lexer::getSourceText(Range, SM, LangOpts).str();
}

bool SAGenTestChecker::isNullLiteral(const Expr *E, ASTContext &ACtx) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (E->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull))
    return true;
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 0;
  return false;
}

const Expr *SAGenTestChecker::extractCheckedExprForNull(const Expr *CondE, CheckerContext &C) {
  if (!CondE) return nullptr;
  const ASTContext &ACtx = C.getASTContext();
  CondE = CondE->IgnoreParenImpCasts();

  // Pattern: if (!X)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr();
      return Sub ? Sub->IgnoreParenImpCasts() : nullptr;
    }
  }

  // Pattern: if (X == NULL) or if (NULL == X)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      bool LNull = isNullLiteral(L, ACtx);
      bool RNull = isNullLiteral(R, ACtx);
      if (LNull && !RNull)
        return R;
      if (RNull && !LNull)
        return L;
    }
  }

  return nullptr;
}

bool SAGenTestChecker::isAllocLikeCall(const CallExpr *CE, CheckerContext &C) {
  if (!CE) return false;

  // First try direct callee name
  std::string Name = getCalleeNameFromCall(CE);
  auto IsAllocName = [&](StringRef N) {
    return Name == N.str() || ExprHasName(CE->getCallee(), N, C);
  };

  // Common kernel allocators
  if (IsAllocName("kzalloc")) return true;
  if (IsAllocName("kvzalloc")) return true;
  if (IsAllocName("kmalloc")) return true;
  if (IsAllocName("kcalloc")) return true;
  if (IsAllocName("krealloc")) return true;
  if (IsAllocName("kmemdup")) return true;

  // devm_ variants too
  if (IsAllocName("devm_kzalloc")) return true;
  if (IsAllocName("devm_kmalloc")) return true;
  if (IsAllocName("devm_kcalloc")) return true;

  return false;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition) return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) return;

  // 1) Recognize a NULL-check-like condition and extract the checked expression.
  const Expr *CheckedE = extractCheckedExprForNull(CondE, C);
  if (!CheckedE) return;

  // 2) Find the enclosing IfStmt for this condition and its containing CompoundStmt.
  const IfStmt *InnerIf = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!InnerIf) return;

  const CompoundStmt *Comp = findSpecificTypeInParents<CompoundStmt>(InnerIf, C);
  if (!Comp) return;

  // 3) Locate the statement immediately preceding the IfStmt within the same block.
  const Stmt *PrevS = nullptr;
  unsigned Index = 0;
  bool Found = false;
  for (const Stmt *S : Comp->body()) {
    if (S == InnerIf) {
      Found = true;
      break;
    }
    ++Index;
  }
  if (!Found || Index == 0)
    return;

  // Retrieve (Index - 1)-th statement as previous.
  unsigned Cur = 0;
  for (const Stmt *S : Comp->body()) {
    if (Cur + 1 == Index) {
      PrevS = S;
      break;
    }
    ++Cur;
  }
  if (!PrevS) return;

  // 4) Ensure the previous statement is an assignment from an allocation call.
  const BinaryOperator *Assign = dyn_cast<BinaryOperator>(PrevS);
  if (!Assign) {
    // Try to find an assignment inside the statement.
    Assign = findSpecificTypeInChildren<BinaryOperator>(PrevS);
  }
  if (!Assign || Assign->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = Assign->getLHS();
  const Expr *RHS = Assign->getRHS();
  if (!LHS || !RHS) return;

  LHS = LHS->IgnoreParenImpCasts();
  RHS = RHS->IgnoreParenImpCasts();

  const CallExpr *AllocCall = dyn_cast<CallExpr>(RHS);
  if (!AllocCall) return;
  if (!isAllocLikeCall(AllocCall, C)) return;

  // 5) Compare the checked expression with the allocated lvalue using regions.
  const MemRegion *AllocReg = getMemRegionFromExpr(LHS, C);
  if (!AllocReg) return;
  const MemRegion *CheckedReg = getMemRegionFromExpr(CheckedE, C);
  if (!CheckedReg) return;

  // Always obtain base regions as suggested (we still keep originals for field info).
  const MemRegion *AllocBase = AllocReg->getBaseRegion();
  const MemRegion *CheckedBase = CheckedReg->getBaseRegion();
  (void)AllocBase;
  (void)CheckedBase;

  // We focus on field-to-field mismatches (siblings within the same parent).
  const auto *AllocField = dyn_cast<FieldRegion>(AllocReg);
  const auto *CheckedField = dyn_cast<FieldRegion>(CheckedReg);
  if (!AllocField || !CheckedField)
    return;

  if (AllocField == CheckedField)
    return; // Correct field checked.

  const MemRegion *AllocParent = AllocField->getSuperRegion();
  const MemRegion *CheckedParent = CheckedField->getSuperRegion();
  if (!AllocParent || !CheckedParent)
    return;

  if (AllocParent != CheckedParent)
    return; // Not siblings in the same object; skip to avoid false positives.

  // Optional confidence boost: if 'then' branch immediately returns, it's likely an error path.
  // This is optional and non-blocking; we don't require it to report.
  (void)InnerIf;

  // 6) Report the bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  std::string CheckedTxt = getExprText(CheckedE, C);
  std::string AllocTxt = getExprText(LHS, C);
  if (CheckedTxt.empty()) CheckedTxt = "the other field";
  if (AllocTxt.empty()) AllocTxt = "allocated field";

  std::string Msg = "Wrong NULL check: checking '" + CheckedTxt +
                    "' after allocating '" + AllocTxt + "'";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(CondE->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects checking the wrong pointer for NULL after an allocation (e.g., checking a different field than the one just allocated)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
