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

File:| /scratch/chenyuan-data/linux-debug/arch/x86/events/intel/uncore_nhmex.c
---|---
Warning:| line 1014, column 33
32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit
before the multiply

### Annotated Source Code


927   | static struct intel_uncore_type nhmex_uncore_mbox = {
928   | 	.name			= "mbox",
929   | 	.num_counters		= 6,
930   | 	.num_boxes		= 2,
931   | 	.perf_ctr_bits		= 48,
932   | 	.event_ctl		= NHMEX_M0_MSR_PMU_CTL0,
933   | 	.perf_ctr		= NHMEX_M0_MSR_PMU_CNT0,
934   | 	.event_mask		= NHMEX_M_PMON_RAW_EVENT_MASK,
935   | 	.box_ctl		= NHMEX_M0_MSR_GLOBAL_CTL,
936   | 	.msr_offset		= NHMEX_M_MSR_OFFSET,
937   | 	.pair_ctr_ctl		= 1,
938   | 	.num_shared_regs	= 8,
939   | 	.event_descs		= nhmex_uncore_mbox_events,
940   | 	.ops			= &nhmex_uncore_mbox_ops,
941   | 	.format_group		= &nhmex_uncore_mbox_format_group,
942   | };
943   |
944   | static void nhmex_rbox_alter_er(struct intel_uncore_box *box, struct perf_event *event)
945   | {
946   |  struct hw_perf_event *hwc = &event->hw;
947   |  struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
948   |
949   |  /* adjust the main event selector and extra register index */
950   |  if (reg1->idx % 2) {
951   | 		reg1->idx--;
952   | 		hwc->config -= 1 << NHMEX_R_PMON_CTL_EV_SEL_SHIFT;
953   | 	} else {
954   | 		reg1->idx++;
955   | 		hwc->config += 1 << NHMEX_R_PMON_CTL_EV_SEL_SHIFT;
956   | 	}
957   |
958   |  /* adjust extra register config */
959   |  switch (reg1->idx % 6) {
960   |  case 2:
961   |  /* shift the 8~15 bits to the 0~7 bits */
962   | 		reg1->config >>= 8;
963   |  break;
964   |  case 3:
965   |  /* shift the 0~7 bits to the 8~15 bits */
966   | 		reg1->config <<= 8;
967   |  break;
968   | 	}
969   | }
970   |
971   | /*
972   |  * Each rbox has 4 event set which monitor PQI port 0~3 or 4~7.
973   |  * An event set consists of 6 events, the 3rd and 4th events in
974   |  * an event set use the same extra register. So an event set uses
975   |  * 5 extra registers.
976   |  */
977   | static struct event_constraint *
978   | nhmex_rbox_get_constraint(struct intel_uncore_box *box, struct perf_event *event)
979   | {
980   |  struct hw_perf_event *hwc = &event->hw;
981   |  struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
982   |  struct hw_perf_event_extra *reg2 = &hwc->branch_reg;
983   |  struct intel_uncore_extra_reg *er;
984   |  unsigned long flags;
985   |  int idx, er_idx;
986   | 	u64 config1;
987   | 	bool ok = false;
988   |
989   |  if (!uncore_box_is_fake(box) && reg1->alloc)
990   |  return NULL;
991   |
992   | 	idx = reg1->idx % 6;
993   |  config1 = reg1->config;
994   | again:
995   | 	er_idx = idx;
996   |  /* the 3rd and 4th events use the same extra register */
997   |  if (er_idx > 2)
    1Assuming 'er_idx' is <= 2→
    2←Taking false branch→
998   | 		er_idx--;
999   |  er_idx += (reg1->idx / 6) * 5;
1000  |
1001  |  er = &box->shared_regs[er_idx];
1002  |  raw_spin_lock_irqsave(&er->lock, flags);
    3←Loop condition is false.  Exiting loop→
1003  |  if (idx < 2) {
    4←Assuming 'idx' is >= 2→
1004  |  if (!atomic_read(&er->ref) || er->config == reg1->config) {
1005  | 			atomic_inc(&er->ref);
1006  | 			er->config = reg1->config;
1007  | 			ok = true;
1008  | 		}
1009  | 	} else if (idx4.1'idx' is equal to 2 == 2 || idx == 3) {
1010  |  /*
1011  |  * these two events use different fields in a extra register,
1012  |  * the 0~7 bits and the 8~15 bits respectively.
1013  |  */
1014  | 		u64 mask = 0xff << ((idx - 2) * 8);
    5←32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply
1015  |  if (!__BITS_VALUE(atomic_read(&er->ref), idx - 2, 8) ||
1016  | 				!((er->config ^ config1) & mask)) {
1017  | 			atomic_add(1 << ((idx - 2) * 8), &er->ref);
1018  | 			er->config &= ~mask;
1019  | 			er->config |= config1 & mask;
1020  | 			ok = true;
1021  | 		}
1022  | 	} else {
1023  |  if (!atomic_read(&er->ref) ||
1024  | 				(er->config == (hwc->config >> 32) &&
1025  | 				 er->config1 == reg1->config &&
1026  | 				 er->config2 == reg2->config)) {
1027  | 			atomic_inc(&er->ref);
1028  | 			er->config = (hwc->config >> 32);
1029  | 			er->config1 = reg1->config;
1030  | 			er->config2 = reg2->config;
1031  | 			ok = true;
1032  | 		}
1033  | 	}
1034  |  raw_spin_unlock_irqrestore(&er->lock, flags);
1035  |
1036  |  if (!ok) {
1037  |  /*
1038  |  * The Rbox events are always in pairs. The paired
1039  |  * events are functional identical, but use different
1040  |  * extra registers. If we failed to take an extra
1041  |  * register, try the alternative.
1042  |  */
1043  | 		idx ^= 1;
1044  |  if (idx != reg1->idx % 6) {

Analysis:
- Decision: NotABug
- Reason: The reported code does not match the target bug pattern and is not a real overflow. The target pattern requires a 32-bit multiply that overflows before being assigned to a 64-bit variable. Here, in u64 mask = 0xff << ((idx - 2) * 8); the multiply is (idx - 2) * 8 with idx = reg1->idx % 6, and the branch ensures idx ∈ {2,3}. Thus (idx - 2) ∈ {0,1}, and the product is 0 or 8—no overflow is possible in 32-bit arithmetic. The left-shift then computes 0xff or 0xff00, both well within 32-bit range, and only then is widened to u64, which is safe. Similarly, atomic_add(1 << ((idx - 2) * 8), ...) produces 1 or 256—again no overflow. Therefore, there is no 32-bit overflow before widening, and this does not fit the specified 32-bit-to-64-bit multiplication overflow bug pattern.

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
