# Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

# Instruction

Please analyze this false positive case and propose fixes to the checker code to eliminate this specific false positive while maintaining detection of true positives.

Please help improve this checker to eliminate the false positive while maintaining its ability to detect actual issues. Your solution should:

1. Identify the root cause of the false positive
2. Propose specific fixes to the checker logic
3. Consider edge cases and possible regressions
4. Maintain compatibility with Clang-18 API

Note, the repaired checker needs to still **detect the target buggy code**.

## Suggestions

1. Use proper visitor patterns and state tracking
2. Handle corner cases gracefully
3. You could register a program state like `REGISTER_MAP_WITH_PROGRAMSTATE(...)` to track the information you need.
4. Follow Clang Static Analyzer best practices for checker development
5. DO NOT remove any existing `#include` in the checker code.

You could add some functions like `bool isFalsePositive(...)` to help you define and detect the false positive.

# Utility Functions

```cpp
// Going upward in an AST tree, and find the Stmt of a specific type
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

// Going downward in an AST tree, and find the Stmt of a secific type
// Only return one of the statements if there are many
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
  Expr::EvalResult ExprRes;
  if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
    EvalRes = ExprRes.Val.getInt();
    return true;
  }
  return false;
}

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
  return maxVal;
}

// The expression should be the DeclRefExpr of the array
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = ArrayType->getSize();
        return true;
      }
    }
  }
  return false;
}

bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
  if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
    StringSize = llvm::APInt(32, SL->getLength());
    return true;
  }
  return false;
}

const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}

struct KnownDerefFunction {
  const char *Name;                    ///< The function name.
  llvm::SmallVector<unsigned, 4> Params; ///< The parameter indices that get dereferenced.
};

/// \brief Determines if the given call is to a function known to dereference
///        certain pointer parameters.
///
/// This function looks up the call's callee name in a known table of functions
/// that definitely dereference one or more of their pointer parameters. If the
/// function is found, it appends the 0-based parameter indices that are dereferenced
/// into \p DerefParams and returns \c true. Otherwise, it returns \c false.
///
/// \param[in] Call        The function call to examine.
/// \param[out] DerefParams
///     A list of parameter indices that the function is known to dereference.
///
/// \return \c true if the function is found in the known-dereference table,
///         \c false otherwise.
bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    for (const auto &Entry : DerefTable) {
      if (FnName.equals(Entry.Name)) {
        // We found the function in our table, copy its param indices
        DerefParams.append(Entry.Params.begin(), Entry.Params.end());
        return true;
      }
    }
  }
  return false;
}

/// \brief Determines if the source text of an expression contains a specified name.
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  // Use const reference since getSourceManager() returns a const SourceManager.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  // Retrieve the source text corresponding to the expression.
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);

  // Check if the extracted text contains the specified name.
  return ExprText.contains(Name);
}
```

# Clang Check Functions

```cpp
void checkPreStmt (const ReturnStmt *DS, CheckerContext &C) const
 // Pre-visit the Statement.

void checkPostStmt (const DeclStmt *DS, CheckerContext &C) const
 // Post-visit the Statement.

void checkPreCall (const CallEvent &Call, CheckerContext &C) const
 // Pre-visit an abstract "call" event.

void checkPostCall (const CallEvent &Call, CheckerContext &C) const
 // Post-visit an abstract "call" event.

void checkBranchCondition (const Stmt *Condition, CheckerContext &Ctx) const
 // Pre-visit of the condition statement of a branch (such as IfStmt).


void checkLocation (SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &) const
 // Called on a load from and a store to a location.

void checkBind (SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const
 // Called on binding of a value to a location.


void checkBeginFunction (CheckerContext &Ctx) const
 // Called when the analyzer core starts analyzing a function, regardless of whether it is analyzed at the top level or is inlined.

void checkEndFunction (const ReturnStmt *RS, CheckerContext &Ctx) const
 // Called when the analyzer core reaches the end of a function being analyzed regardless of whether it is analyzed at the top level or is inlined.

void checkEndAnalysis (ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const
 // Called after all the paths in the ExplodedGraph reach end of path.


bool evalCall (const CallEvent &Call, CheckerContext &C) const
 // Evaluates function call.

ProgramStateRef evalAssume (ProgramStateRef State, SVal Cond, bool Assumption) const
 // Handles assumptions on symbolic values.

ProgramStateRef checkRegionChanges (ProgramStateRef State, const InvalidatedSymbols *Invalidated, ArrayRef< const MemRegion * > ExplicitRegions, ArrayRef< const MemRegion * > Regions, const LocationContext *LCtx, const CallEvent *Call) const
 // Called when the contents of one or more regions change.

void checkASTDecl (const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration in the AST.

void checkASTCodeBody (const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration that has a statement body in the AST.
```


The following pattern is the checker designed to detect:

## Bug Pattern

Computing a size using 32-bit arithmetic and only then assigning it to a 64-bit variable, causing overflow before the assignment. Specifically, multiplying two 32-bit operands (e.g., u32 mall_size_per_umc and u32 num_umc) without promoting to 64-bit first:

u64 total = (u32)a * (u32)b;  // overflow happens in 32-bit
// Correct:
u64 total = (u64)a * b;  // force 64-bit arithmetic before assignment

This pattern arises when size/count calculations use narrower integer types for intermediate arithmetic even though the result is stored in a wider type.

The patch that needs to be detected:

## Patch Description

drm/amdgu: fix Unintentional integer overflow for mall size

Potentially overflowing expression mall_size_per_umc * adev->gmc.num_umc with type unsigned int (32 bits, unsigned)
is evaluated using 32-bit arithmetic,and then used in a context that expects an expression of type u64 (64 bits, unsigned).

Signed-off-by: Jesse Zhang <Jesse.Zhang@amd.com>
Reviewed-by: Christian König <christian.koenig@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>

## Buggy Code

```c
// Function: amdgpu_discovery_get_mall_info in drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
static int amdgpu_discovery_get_mall_info(struct amdgpu_device *adev)
{
	struct binary_header *bhdr;
	union mall_info *mall_info;
	u32 u, mall_size_per_umc, m_s_present, half_use;
	u64 mall_size;
	u16 offset;

	if (!adev->mman.discovery_bin) {
		DRM_ERROR("ip discovery uninitialized\n");
		return -EINVAL;
	}

	bhdr = (struct binary_header *)adev->mman.discovery_bin;
	offset = le16_to_cpu(bhdr->table_list[MALL_INFO].offset);

	if (!offset)
		return 0;

	mall_info = (union mall_info *)(adev->mman.discovery_bin + offset);

	switch (le16_to_cpu(mall_info->v1.header.version_major)) {
	case 1:
		mall_size = 0;
		mall_size_per_umc = le32_to_cpu(mall_info->v1.mall_size_per_m);
		m_s_present = le32_to_cpu(mall_info->v1.m_s_present);
		half_use = le32_to_cpu(mall_info->v1.m_half_use);
		for (u = 0; u < adev->gmc.num_umc; u++) {
			if (m_s_present & (1 << u))
				mall_size += mall_size_per_umc * 2;
			else if (half_use & (1 << u))
				mall_size += mall_size_per_umc / 2;
			else
				mall_size += mall_size_per_umc;
		}
		adev->gmc.mall_size = mall_size;
		adev->gmc.m_half_use = half_use;
		break;
	case 2:
		mall_size_per_umc = le32_to_cpu(mall_info->v2.mall_size_per_umc);
		adev->gmc.mall_size = mall_size_per_umc * adev->gmc.num_umc;
		break;
	default:
		dev_err(adev->dev,
			"Unhandled MALL info table %d.%d\n",
			le16_to_cpu(mall_info->v1.header.version_major),
			le16_to_cpu(mall_info->v1.header.version_minor));
		return -EINVAL;
	}
	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
index 87b31ed8de19..c71356cb393d 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
@@ -1629,7 +1629,7 @@ static int amdgpu_discovery_get_mall_info(struct amdgpu_device *adev)
 		break;
 	case 2:
 		mall_size_per_umc = le32_to_cpu(mall_info->v2.mall_size_per_umc);
-		adev->gmc.mall_size = mall_size_per_umc * adev->gmc.num_umc;
+		adev->gmc.mall_size = (uint64_t)mall_size_per_umc * adev->gmc.num_umc;
 		break;
 	default:
 		dev_err(adev->dev,
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/drivers/irqchip/exynos-combiner.c
---|---
Warning:| line 148, column 26
32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit
before the multiply

### Annotated Source Code


86    | 		handle_bad_irq(desc);
87    |
88    |  out:
89    | 	chained_irq_exit(chip, desc);
90    | }
91    |
92    | #ifdef CONFIG_SMP
93    | static int combiner_set_affinity(struct irq_data *d,
94    |  const struct cpumask *mask_val, bool force)
95    | {
96    |  struct combiner_chip_data *chip_data = irq_data_get_irq_chip_data(d);
97    |  struct irq_chip *chip = irq_get_chip(chip_data->parent_irq);
98    |  struct irq_data *data = irq_get_irq_data(chip_data->parent_irq);
99    |
100   |  if (chip && chip->irq_set_affinity)
101   |  return chip->irq_set_affinity(data, mask_val, force);
102   |  else
103   |  return -EINVAL;
104   | }
105   | #endif
106   |
107   | static struct irq_chip combiner_chip = {
108   | 	.name			= "COMBINER",
109   | 	.irq_mask		= combiner_mask_irq,
110   | 	.irq_unmask		= combiner_unmask_irq,
111   | #ifdef CONFIG_SMP
112   | 	.irq_set_affinity	= combiner_set_affinity,
113   | #endif
114   | };
115   |
116   | static void __init combiner_cascade_irq(struct combiner_chip_data *combiner_data,
117   |  unsigned int irq)
118   | {
119   | 	irq_set_chained_handler_and_data(irq, combiner_handle_cascade_irq,
120   | 					 combiner_data);
121   | }
122   |
123   | static void __init combiner_init_one(struct combiner_chip_data *combiner_data,
124   |  unsigned int combiner_nr,
125   |  void __iomem *base, unsigned int irq)
126   | {
127   | 	combiner_data->base = base;
128   | 	combiner_data->hwirq_offset = (combiner_nr & ~3) * IRQ_IN_COMBINER;
129   | 	combiner_data->irq_mask = 0xff << ((combiner_nr % 4) << 3);
130   | 	combiner_data->parent_irq = irq;
131   |
132   |  /* Disable all interrupts */
133   |  writel_relaxed(combiner_data->irq_mask, base + COMBINER_ENABLE_CLEAR);
134   | }
135   |
136   | static int combiner_irq_domain_xlate(struct irq_domain *d,
137   |  struct device_node *controller,
138   |  const u32 *intspec, unsigned int intsize,
139   |  unsigned long *out_hwirq,
140   |  unsigned int *out_type)
141   | {
142   |  if (irq_domain_get_of_node(d) != controller)
    1Assuming the condition is false→
    2←Taking false branch→
143   |  return -EINVAL;
144   |
145   |  if (intsize < 2)
    3←Assuming 'intsize' is >= 2→
    4←Taking false branch→
146   |  return -EINVAL;
147   |
148   |  *out_hwirq = intspec[0] * IRQ_IN_COMBINER + intspec[1];
    5←32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply
149   | 	*out_type = 0;
150   |
151   |  return 0;
152   | }
153   |
154   | static int combiner_irq_domain_map(struct irq_domain *d, unsigned int irq,
155   | 				   irq_hw_number_t hw)
156   | {
157   |  struct combiner_chip_data *combiner_data = d->host_data;
158   |
159   | 	irq_set_chip_and_handler(irq, &combiner_chip, handle_level_irq);
160   | 	irq_set_chip_data(irq, &combiner_data[hw >> 3]);
161   | 	irq_set_probe(irq);
162   |
163   |  return 0;
164   | }
165   |
166   | static const struct irq_domain_ops combiner_irq_domain_ops = {
167   | 	.xlate	= combiner_irq_domain_xlate,
168   | 	.map	= combiner_irq_domain_map,
169   | };
170   |
171   | static void __init combiner_init(void __iomem *combiner_base,
172   |  struct device_node *np)
173   | {
174   |  int i, irq;
175   |  unsigned int nr_irq;
176   |
177   | 	nr_irq = max_nr * IRQ_IN_COMBINER;
178   |

Analysis:
- Decision: NotABug
- Reason: The flagged line computes a hardware interrupt number: *out_hwirq = intspec[0] * IRQ_IN_COMBINER + intspec[1]. Here, intspec elements are u32 and IRQ_IN_COMBINER is a small constant (typically 8). The destination out_hwirq is unsigned long (32-bit on 32-bit arch, 64-bit on 64-bit arch). Although the multiply occurs in 32-bit due to operand types, the operands’ realistic ranges make 32-bit overflow infeasible: intspec[0] is a device-tree “combiner index” with practical values in the tens at most, so intspec[0] * 8 stays far below 2^32. The target bug pattern concerns size/count multiplications that overflow 32-bit before assignment to a 64-bit variable; this code is not a size calculation and does not risk overflow for any real-world input. On 32-bit architectures there isn’t even a 64-bit widening. Thus, this is a false positive relative to the specified pattern and not a real bug.

# Checker
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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<BinaryOperator>> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "32-bit multiply widened to 64-bit",
                       "Integer Overflow")) {}

  void checkPostStmt(const BinaryOperator *B, CheckerContext &C) const;

private:
  // Helpers
  static unsigned getIntWidth(QualType T, CheckerContext &C) {
    return C.getASTContext().getIntWidth(T);
  }

  static bool isInt64OrWider(QualType T, CheckerContext &C) {
    return T->isIntegerType() && getIntWidth(T, C) >= 64;
  }

  static bool isIntegerType(const Expr *E) {
    if (!E) return false;
    return E->getType()->isIntegerType();
  }

  // Determine if the expression result is used in a 64-bit integer context.
  bool isWidenedUseTo64(const Expr *E, CheckerContext &C) const {
    if (!E) return false;

    // 1) Look for an implicit cast to 64-bit integer.
    if (const auto *ICE = findSpecificTypeInParents<ImplicitCastExpr>(E, C)) {
      QualType DestTy = ICE->getType();
      if (isInt64OrWider(DestTy, C))
        return true;
    }

    // 2) Look for a C-style cast to 64-bit
    if (const auto *CS = findSpecificTypeInParents<CStyleCastExpr>(E, C)) {
      QualType DestTy = CS->getTypeAsWritten();
      if (isInt64OrWider(DestTy, C))
        return true;
    }

    // 3) Look for assignment where LHS is 64-bit
    if (const auto *PAssn = findSpecificTypeInParents<BinaryOperator>(E, C)) {
      if (PAssn->isAssignmentOp()) {
        const Expr *LHS = PAssn->getLHS();
        if (LHS && isInt64OrWider(LHS->getType(), C))
          return true;
      }
    }

    // 4) Look for return statement where function returns 64-bit
    if (findSpecificTypeInParents<ReturnStmt>(E, C)) {
      const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
      if (D) {
        QualType RetTy = D->getReturnType();
        if (isInt64OrWider(RetTy, C))
          return true;
      }
    }

    // 5) Look for function call argument where the parameter is 64-bit
    if (const auto *Call = findSpecificTypeInParents<CallExpr>(E, C)) {
      const FunctionDecl *FD = Call->getDirectCallee();
      if (!FD)
        return false;
      for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
        const Expr *Arg = Call->getArg(i);
        if (!Arg)
          continue;
        const Expr *ArgCore = Arg->IgnoreParenImpCasts();
        const Expr *ECore = E->IgnoreParenImpCasts();
        if (ArgCore == ECore) {
          QualType ParamTy = FD->getParamDecl(i)->getType();
          if (isInt64OrWider(ParamTy, C))
            return true;
        }
      }
    }

    return false;
  }

  // Try to get the maximum possible value of an expression.
  bool getMaxForExpr(const Expr *E, CheckerContext &C, llvm::APSInt &Out) const {
    if (!E) return false;

    // Try constant evaluation
    if (EvaluateExprToInt(Out, E, C))
      return true;

    // Try symbolic max value
    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(E, C.getLocationContext());
    SymbolRef Sym = V.getAsSymbol();
    if (!Sym)
      return false;

    if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
      Out = *MaxV;
      return true;
    }
    return false;
  }

  // Check if we can prove the product fits into the narrow type; if yes, suppress.
  bool productDefinitelyFits(const BinaryOperator *B, CheckerContext &C) const {
    if (!B) return false;
    const Expr *LHS = B->getLHS();
    const Expr *RHS = B->getRHS();
    if (!LHS || !RHS)
      return false;

    llvm::APSInt MaxL, MaxR;
    if (!getMaxForExpr(LHS, C, MaxL) || !getMaxForExpr(RHS, C, MaxR))
      return false; // Can't prove, so not definitely safe.

    // Compute product with 128-bit headroom using unsigned math.
    uint64_t ML = MaxL.getZExtValue();
    uint64_t MR = MaxR.getZExtValue();
    __uint128_t Prod = ( (__uint128_t)ML ) * ( (__uint128_t)MR );

    // Determine limit for the narrow type (result type of the multiply).
    unsigned MulW = getIntWidth(B->getType(), C);
    bool IsUnsigned = B->getType()->isUnsignedIntegerType();
    __uint128_t Limit;
    if (IsUnsigned) {
      if (MulW >= 64) {
        // If multiply is already 64-bit or more (should not be here), treat as safe.
        return true;
      }
      Limit = (((__uint128_t)1) << MulW) - 1;
    } else {
      if (MulW == 0)
        return false;
      if (MulW >= 64) {
        // As above, treat as safe (won't reach in typical flow).
        return true;
      }
      // Signed max: 2^(W-1) - 1
      Limit = (((__uint128_t)1) << (MulW - 1)) - 1;
    }

    return Prod <= Limit;
  }
};

void SAGenTestChecker::checkPostStmt(const BinaryOperator *B, CheckerContext &C) const {
  if (!B)
    return;

  // Only care about integer multiplication.
  if (B->getOpcode() != BO_Mul)
    return;
  if (!B->getType()->isIntegerType())
    return;

  // The multiply's arithmetic width (after integer promotions).
  unsigned MulWidth = getIntWidth(B->getType(), C);

  // If arithmetic is already 64-bit or more, that's OK.
  if (MulWidth >= 64)
    return;

  // Ensure operands are integer-typed as well.
  if (!isIntegerType(B->getLHS()) || !isIntegerType(B->getRHS()))
    return;

  // Is the result used in 64-bit integer context?
  const Expr *E = dyn_cast<Expr>(B);
  if (!E)
    return;

  if (!isWidenedUseTo64(E, C))
    return;

  // Optional reduction: if we can prove product fits in the narrow type, don't warn.
  if (productDefinitelyFits(B, C))
    return;

  // Report: multiplication in 32-bit (or narrower) that is widened to 64-bit.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply",
      N);
  R->addRange(B->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect 32-bit multiply whose result is only widened to 64-bit afterward, risking overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

# Formatting

Please provide the whole checker code after fixing the false positive.
The refined code must be surrounded by ```cpp and ```.
Your response should be like:

Refinment Plan:
XXX

Refined Code:
```cpp
{{fixed checker code here}}
```
