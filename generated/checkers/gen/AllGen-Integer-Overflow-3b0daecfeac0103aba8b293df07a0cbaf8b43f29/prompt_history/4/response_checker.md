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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Overflow-prone kmalloc/kzalloc size", "Memory Management")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Helper: match function name reliably using ExprHasName as suggested.
      bool calleeNameIs(const CallEvent &Call, StringRef Name, CheckerContext &C) const {
        const Expr *OE = Call.getOriginExpr();
        if (OE && ExprHasName(OE, Name, C))
          return true;
        if (const IdentifierInfo *II = Call.getCalleeIdentifier())
          return II->getName() == Name;
        return false;
      }

      bool isOverflowProneAllocator(const CallEvent &Call, CheckerContext &C) const {
        return calleeNameIs(Call, "kmalloc", C) ||
               calleeNameIs(Call, "kzalloc", C) ||
               calleeNameIs(Call, "kmalloc_node", C) ||
               calleeNameIs(Call, "kzalloc_node", C);
      }

      bool isOverflowCheckedAllocator(const CallEvent &Call, CheckerContext &C) const {
        return calleeNameIs(Call, "kcalloc", C) ||
               calleeNameIs(Call, "kvcalloc", C) ||
               calleeNameIs(Call, "kcalloc_node", C) ||
               calleeNameIs(Call, "kvcalloc_node", C) ||
               calleeNameIs(Call, "kmalloc_array", C);
      }

      bool isConstExpr(const Expr *E, CheckerContext &C) const {
        if (!E) return false;
        llvm::APSInt Tmp;
        return EvaluateExprToInt(Tmp, E, C);
      }

      // Find a multiplication in SizeArg and split operands:
      // one must contain sizeof(...), the other is the "count".
      bool findMulAndSplit(const Expr *SizeArg,
                           const BinaryOperator *&MulBO,
                           const Expr *&ElementSizeExpr,
                           const Expr *&CountExpr,
                           CheckerContext &C) const {
        if (!SizeArg) return false;
        MulBO = findSpecificTypeInChildren<BinaryOperator>(SizeArg);
        if (!MulBO || MulBO->getOpcode() != BO_Mul)
          return false;

        const Expr *L = MulBO->getLHS();
        const Expr *R = MulBO->getRHS();
        if (!L || !R) return false;

        const auto *LSize = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(L);
        const auto *RSize = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(R);

        bool LHasSize = LSize && LSize->getKind() == UETT_SizeOf;
        bool RHasSize = RSize && RSize->getKind() == UETT_SizeOf;

        // Require sizeof to be clearly on exactly one side.
        if (LHasSize == RHasSize)
          return false;

        if (LHasSize) {
          ElementSizeExpr = L;
          CountExpr = R;
        } else {
          ElementSizeExpr = R;
          CountExpr = L;
        }
        return true;
      }

      // Optional suppression using symbolic upper bound reasoning.
      bool proveNoOverflow(const CallEvent &Call,
                           const Expr *ElementSizeExpr,
                           const Expr *CountExpr,
                           CheckerContext &C) const {
        if (!ElementSizeExpr || !CountExpr)
          return false;

        // Get element size as integer.
        llvm::APSInt ElemSizeAPS;
        if (!EvaluateExprToInt(ElemSizeAPS, ElementSizeExpr, C))
          return false; // fail-open

        uint64_t ElemSizeZ = ElemSizeAPS.getZExtValue();
        if (ElemSizeZ == 0)
          return false; // pathological, fail-open

        // Try to obtain a symbol for CountExpr.
        ProgramStateRef State = C.getState();
        SVal CountSV = State->getSVal(CountExpr, C.getLocationContext());
        SymbolRef CountSym = CountSV.getAsSymbol();
        if (!CountSym)
          return false; // fail-open

        const llvm::APSInt *MaxCountAPS = inferSymbolMaxVal(CountSym, C);
        if (!MaxCountAPS)
          return false; // fail-open

        // Compute maximum allowed count = SIZE_MAX / ElemSize.
        unsigned W = C.getASTContext().getTypeSize(Call.getArgExpr(0)->getType());
        if (W == 0)
          return false;

        llvm::APInt SizeMaxAP(W, 0);
        SizeMaxAP.setAllBits(); // SIZE_MAX for given width

        llvm::APInt ElemAP(W, ElemSizeZ); // zero-extended into width W

        if (ElemAP == 0)
          return false;

        llvm::APInt BoundAP = SizeMaxAP.udiv(ElemAP);

        uint64_t BoundZ = BoundAP.getLimitedValue(UINT64_MAX);
        uint64_t MaxCountZ = MaxCountAPS->getZExtValue(); // best-effort

        // If the maximum possible count fits into the safe bound, suppress warning.
        return MaxCountZ <= BoundZ;
      }

      void report(const CallEvent &Call, const Stmt *LocStmt, CheckerContext &C) const {
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N)
          return;

        auto R = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "Use kcalloc/kvcalloc(count, size) instead of kmalloc/kzalloc(count*size); multiplication may overflow.",
          N);

        if (LocStmt)
          R->addRange(LocStmt->getSourceRange());

        C.emitReport(std::move(R));
      }
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Skip if already using overflow-checked helpers.
  if (isOverflowCheckedAllocator(Call, C))
    return;

  // Focus on kmalloc/kzalloc and their _node variants.
  if (!isOverflowProneAllocator(Call, C))
    return;

  if (Call.getNumArgs() == 0)
    return;

  const Expr *SizeArg = Call.getArgExpr(0);
  if (!SizeArg)
    return;

  // Require multiplication present.
  const BinaryOperator *MulBO = nullptr;
  const Expr *ElementSizeExpr = nullptr;
  const Expr *CountExpr = nullptr;
  if (!findMulAndSplit(SizeArg, MulBO, ElementSizeExpr, CountExpr, C))
    return;

  // Require sizeof(...) to be present in exactly one operand (ensured by findMulAndSplit).

  // Skip if the entire size is a compile-time constant.
  if (isConstExpr(SizeArg, C))
    return;

  // Skip if the count is a compile-time constant (to reduce noise on fixed sizes).
  if (isConstExpr(CountExpr, C))
    return;

  // Optional suppression: if we can prove no overflow can happen for count*elem_size.
  if (proveNoOverflow(Call, ElementSizeExpr, CountExpr, C))
    return;

  // Report at the multiplication site if possible.
  const Stmt *LocStmt = MulBO ? static_cast<const Stmt*>(MulBO) : static_cast<const Stmt*>(SizeArg);
  report(Call, LocStmt, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects kmalloc/kzalloc with size computed as count*element_size; suggest kcalloc/kvcalloc to avoid integer overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
