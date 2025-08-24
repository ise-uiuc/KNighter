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

Left-shifting a 32-bit expression and only widening to 64-bit after the shift, causing the shift to be performed in 32-bit width and overflow/truncation before assignment:

u64 tau4 = ((1 << x_w) | x) << y;   // shift happens in 32-bit -> overflow
// Correct:
u64 tau4 = (u64)((1 << x_w) | x) << y;

Root cause: the shift is evaluated in the type of the left operand (u32), so bits are lost when y or the result exceeds 32 bits; casting must occur before the shift.

The patch that needs to be detected:

## Patch Description

drm/i915/hwmon: Fix static analysis tool reported issues

Updated i915 hwmon with fixes for issues reported by static analysis tool.
Fixed integer overflow with upcasting.

v2:
- Added Fixes tag (Badal).
- Updated commit message as per review comments (Anshuman).

Fixes: 4c2572fe0ae7 ("drm/i915/hwmon: Expose power1_max_interval")
Reviewed-by: Badal Nilawar <badal.nilawar@intel.com>
Reviewed-by: Anshuman Gupta <anshuman.gupta@intel.com>
Signed-off-by: Karthik Poosa <karthik.poosa@intel.com>
Signed-off-by: Anshuman Gupta <anshuman.gupta@intel.com>
Link: https://patchwork.freedesktop.org/patch/msgid/20231204144809.1518704-1-karthik.poosa@intel.com
(cherry picked from commit ac3420d3d428443a08b923f9118121c170192b62)
Signed-off-by: Jani Nikula <jani.nikula@intel.com>

## Buggy Code

```c
// Function: hwm_power1_max_interval_store in drivers/gpu/drm/i915/i915_hwmon.c
static ssize_t
hwm_power1_max_interval_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct hwm_drvdata *ddat = dev_get_drvdata(dev);
	struct i915_hwmon *hwmon = ddat->hwmon;
	u32 x, y, rxy, x_w = 2; /* 2 bits */
	u64 tau4, r, max_win;
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret)
		return ret;

	/*
	 * Max HW supported tau in '1.x * power(2,y)' format, x = 0, y = 0x12
	 * The hwmon->scl_shift_time default of 0xa results in a max tau of 256 seconds
	 */
#define PKG_MAX_WIN_DEFAULT 0x12ull

	/*
	 * val must be < max in hwmon interface units. The steps below are
	 * explained in i915_power1_max_interval_show()
	 */
	r = FIELD_PREP(PKG_MAX_WIN, PKG_MAX_WIN_DEFAULT);
	x = REG_FIELD_GET(PKG_MAX_WIN_X, r);
	y = REG_FIELD_GET(PKG_MAX_WIN_Y, r);
	tau4 = ((1 << x_w) | x) << y;
	max_win = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

	if (val > max_win)
		return -EINVAL;

	/* val in hw units */
	val = DIV_ROUND_CLOSEST_ULL((u64)val << hwmon->scl_shift_time, SF_TIME);
	/* Convert to 1.x * power(2,y) */
	if (!val) {
		/* Avoid ilog2(0) */
		y = 0;
		x = 0;
	} else {
		y = ilog2(val);
		/* x = (val - (1 << y)) >> (y - 2); */
		x = (val - (1ul << y)) << x_w >> y;
	}

	rxy = REG_FIELD_PREP(PKG_PWR_LIM_1_TIME_X, x) | REG_FIELD_PREP(PKG_PWR_LIM_1_TIME_Y, y);

	hwm_locked_with_pm_intel_uncore_rmw(ddat, hwmon->rg.pkg_rapl_limit,
					    PKG_PWR_LIM_1_TIME, rxy);
	return count;
}
```

```c
// Function: hwm_power1_max_interval_show in drivers/gpu/drm/i915/i915_hwmon.c
static ssize_t
hwm_power1_max_interval_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct hwm_drvdata *ddat = dev_get_drvdata(dev);
	struct i915_hwmon *hwmon = ddat->hwmon;
	intel_wakeref_t wakeref;
	u32 r, x, y, x_w = 2; /* 2 bits */
	u64 tau4, out;

	with_intel_runtime_pm(ddat->uncore->rpm, wakeref)
		r = intel_uncore_read(ddat->uncore, hwmon->rg.pkg_rapl_limit);

	x = REG_FIELD_GET(PKG_PWR_LIM_1_TIME_X, r);
	y = REG_FIELD_GET(PKG_PWR_LIM_1_TIME_Y, r);
	/*
	 * tau = 1.x * power(2,y), x = bits(23:22), y = bits(21:17)
	 *     = (4 | x) << (y - 2)
	 * where (y - 2) ensures a 1.x fixed point representation of 1.x
	 * However because y can be < 2, we compute
	 *     tau4 = (4 | x) << y
	 * but add 2 when doing the final right shift to account for units
	 */
	tau4 = ((1 << x_w) | x) << y;
	/* val in hwmon interface units (millisec) */
	out = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

	return sysfs_emit(buf, "%llu\n", out);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/i915/i915_hwmon.c b/drivers/gpu/drm/i915/i915_hwmon.c
index 975da8e7f2a9..8c3f443c8347 100644
--- a/drivers/gpu/drm/i915/i915_hwmon.c
+++ b/drivers/gpu/drm/i915/i915_hwmon.c
@@ -175,7 +175,7 @@ hwm_power1_max_interval_show(struct device *dev, struct device_attribute *attr,
 	 *     tau4 = (4 | x) << y
 	 * but add 2 when doing the final right shift to account for units
 	 */
-	tau4 = ((1 << x_w) | x) << y;
+	tau4 = (u64)((1 << x_w) | x) << y;
 	/* val in hwmon interface units (millisec) */
 	out = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

@@ -211,7 +211,7 @@ hwm_power1_max_interval_store(struct device *dev,
 	r = FIELD_PREP(PKG_MAX_WIN, PKG_MAX_WIN_DEFAULT);
 	x = REG_FIELD_GET(PKG_MAX_WIN_X, r);
 	y = REG_FIELD_GET(PKG_MAX_WIN_Y, r);
-	tau4 = ((1 << x_w) | x) << y;
+	tau4 = (u64)((1 << x_w) | x) << y;
 	max_win = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

 	if (val > max_win)
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/drivers/char/agp/intel-gtt.c
---|---
Warning:| line 1437, column 16
Shift done in 32-bit, widened after; cast left operand to 64-bit before <<

### Annotated Source Code


1381  | 	}
1382  |
1383  |  if (!intel_private.driver)
1384  |  return 0;
1385  |
1386  | #if IS_ENABLED(CONFIG_AGP_INTEL)
1387  |  if (bridge) {
1388  |  if (INTEL_GTT_GEN > 1)
1389  |  return 0;
1390  |
1391  | 		bridge->driver = &intel_fake_agp_driver;
1392  | 		bridge->dev_private_data = &intel_private;
1393  | 		bridge->dev = bridge_pdev;
1394  | 	}
1395  | #endif
1396  |
1397  |
1398  |  /*
1399  |  * Can be called from the fake agp driver but also directly from
1400  |  * drm/i915.ko. Hence we need to check whether everything is set up
1401  |  * already.
1402  |  */
1403  |  if (intel_private.refcount++)
1404  |  return 1;
1405  |
1406  | 	intel_private.bridge_dev = pci_dev_get(bridge_pdev);
1407  |
1408  |  dev_info(&bridge_pdev->dev, "Intel %s Chipset\n", intel_gtt_chipsets[i].name);
1409  |
1410  |  if (bridge) {
1411  | 		mask = intel_private.driver->dma_mask_size;
1412  |  if (dma_set_mask(&intel_private.pcidev->dev, DMA_BIT_MASK(mask)))
1413  |  dev_err(&intel_private.pcidev->dev,
1414  |  "set gfx device dma mask %d-bit failed!\n",
1415  |  mask);
1416  |  else
1417  | 			dma_set_coherent_mask(&intel_private.pcidev->dev,
1418  |  DMA_BIT_MASK(mask));
1419  | 	}
1420  |
1421  |  if (intel_gtt_init() != 0) {
1422  | 		intel_gmch_remove();
1423  |
1424  |  return 0;
1425  | 	}
1426  |
1427  |  return 1;
1428  | }
1429  | EXPORT_SYMBOL(intel_gmch_probe);
1430  |
1431  | void intel_gmch_gtt_get(u64 *gtt_total,
1432  | 			phys_addr_t *mappable_base,
1433  | 			resource_size_t *mappable_end)
1434  | {
1435  |  *gtt_total = intel_private.gtt_total_entries << PAGE_SHIFT;
1436  | 	*mappable_base = intel_private.gma_bus_addr;
1437  |  *mappable_end = intel_private.gtt_mappable_entries << PAGE_SHIFT;
    Shift done in 32-bit, widened after; cast left operand to 64-bit before <<
1438  | }
1439  | EXPORT_SYMBOL(intel_gmch_gtt_get);
1440  |
1441  | void intel_gmch_gtt_flush(void)
1442  | {
1443  |  if (intel_private.driver->chipset_flush)
1444  | 		intel_private.driver->chipset_flush();
1445  | }
1446  | EXPORT_SYMBOL(intel_gmch_gtt_flush);
1447  |
1448  | void intel_gmch_remove(void)
1449  | {
1450  |  if (--intel_private.refcount)
1451  |  return;
1452  |
1453  |  if (intel_private.scratch_page)
1454  | 		intel_gtt_teardown_scratch_page();
1455  |  if (intel_private.pcidev)
1456  | 		pci_dev_put(intel_private.pcidev);
1457  |  if (intel_private.bridge_dev)
1458  | 		pci_dev_put(intel_private.bridge_dev);
1459  | 	intel_private.driver = NULL;
1460  | }
1461  | EXPORT_SYMBOL(intel_gmch_remove);
1462  |
1463  | MODULE_AUTHOR("Dave Jones, Various @Intel");
1464  | MODULE_LICENSE("GPL and additional rights");

Analysis:
- Decision: NotABug
- Reason: The flagged code assigns a shifted 32-bit value to a potentially wider type:
  - *mappable_end = intel_private.gtt_mappable_entries << PAGE_SHIFT;
  - Here, gtt_mappable_entries is a 32-bit count of pages; PAGE_SHIFT is typically 12 (or up to 16 on some arches), so the expression is evaluated in 32-bit. The report claims a 32→64-bit widening after the shift could lose bits.
  - For truncation to occur, the 32-bit shift result would need to exceed 0xffffffff. With PAGE_SHIFT=12, that requires gtt_mappable_entries >= 2^20 (1,048,576), i.e., a mappable size > 4 GiB. This is not feasible for the AGP-era Intel GTT hardware this driver targets; typical apertures are <= 1 GiB (and often 128–512 MiB), so the shifted byte size remains well within 32-bit.
  - On 32-bit architectures, resource_size_t is 32-bit anyway; on 64-bit, even though resource_size_t is 64-bit, the 32-bit shift result still exactly represents the required value (no high bits to lose).
  - Thus, while the expression matches the syntactic pattern (32-bit shift then assignment to a wider type), there is no realistic scenario where overflow/truncation occurs before the assignment. No upstream fix is necessary to change behavior here, and the reported case does not demonstrate the harmful root cause described by the target bug pattern.

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
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/ImmutableMap.h"
#include <algorithm>
#include <cctype>
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the user prompt (assumed available)
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
bool functionKnownToDeref(const CallEvent &Call, llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

// Track per-variable coarse upper bounds learned from assignments.
// Key: VarDecl*, Value: APSInt upper bound (unsigned).
namespace {
struct VarUpperBoundMap {};
// Track exact integer-constant assignments for variables within a function.
// Key: VarDecl*, Value: exact APSInt value assigned via literal/constant expression.
struct VarConstMap {};
}

namespace clang {
namespace ento {
template <>
struct ProgramStateTrait<VarUpperBoundMap>
    : public ProgramStatePartialTrait<llvm::ImmutableMap<const VarDecl *, llvm::APSInt>> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<VarConstMap>
    : public ProgramStatePartialTrait<llvm::ImmutableMap<const VarDecl *, llvm::APSInt>> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};
} // namespace ento
} // namespace clang

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PreStmt<ReturnStmt>,
        check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow shift widened to 64-bit", "Integer")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                   CheckerContext &C, StringRef Ctx) const;

  static const BinaryOperator *findShiftInTree(const Stmt *S);
  static bool hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx);

  static const Expr *peel(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  static const BinaryOperator *asShift(const Stmt *S) {
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_Shl)
        return BO;
    }
    return nullptr;
  }

  static bool isTopLevelShiftExpr(const Expr *ContainerE, const BinaryOperator *Shl) {
    if (!ContainerE || !Shl)
      return false;
    const Expr *Top = peel(ContainerE);
    return Top == static_cast<const Expr *>(Shl);
  }

  // Check if constant L and R guarantee that (L << R) fits within OpW bits (the
  // promoted width of the shift expression).
  static bool constantShiftFitsInWidth(const Expr *L, const Expr *R,
                                       unsigned OpW, CheckerContext &C) {
    llvm::APSInt LHSEval, RHSEval;
    if (!EvaluateExprToInt(LHSEval, L, C))
      return false;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;

    if (LHSEval.isSigned() && LHSEval.isNegative())
      return false;

    unsigned LBits = LHSEval.getActiveBits();
    uint64_t ShiftAmt = RHSEval.getZExtValue();
    if (LBits == 0)
      return true;
    return (uint64_t)LBits + ShiftAmt <= (uint64_t)OpW;
  }

  static bool isAnyLongType(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::Long) ||
           QT->isSpecificBuiltinType(BuiltinType::ULong);
  }

  static bool isFixed64Builtin(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::LongLong) ||
           QT->isSpecificBuiltinType(BuiltinType::ULongLong);
  }

  static bool calleeNameLooksLikeIOOrReg(StringRef Name) {
    llvm::SmallString<64> Lower(Name);
    for (char &c : Lower)
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    StringRef S(Lower);
    return S.contains("read") || S.contains("write") || S.contains("peek") ||
           S.contains("poke") || S.contains("in") || S.contains("out") ||
           S.contains("io") || S.contains("reg");
  }

  static bool paramNameLooksLikeAddrOffset(const ParmVarDecl *P) {
    if (!P)
      return false;
    StringRef N = P->getName();
    if (N.empty())
      return false;

    llvm::SmallString<64> Lower(N);
    for (char &c : Lower)
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    StringRef S(Lower);
    return S.contains("addr") || S.contains("address") || S.contains("offset") ||
           S.contains("ofs") || S.contains("reg") || S.contains("index") ||
           S.contains("port") || S.contains("bar");
  }

  static bool tryGetConstShiftAmount(const Expr *R, CheckerContext &C, uint64_t &Out) {
    llvm::APSInt RHSEval;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;
    Out = RHSEval.getZExtValue();
    return true;
  }

  static bool findCallParentAndArgIndex(const Expr *E, CheckerContext &C,
                                        const CallExpr *&OutCE, unsigned &OutIdx) {
    OutCE = findSpecificTypeInParents<CallExpr>(E, C);
    if (!OutCE)
      return false;

    const Expr *PE = peel(E);
    unsigned ArgCount = OutCE->getNumArgs();
    for (unsigned i = 0; i < ArgCount; ++i) {
      const Expr *AE = OutCE->getArg(i);
      if (peel(AE) == PE) {
        OutIdx = i;
        return true;
      }
    }
    return false;
  }

  static bool isFalsePositiveContext(const Expr *WholeExpr,
                                     const BinaryOperator *Shl,
                                     QualType DestTy,
                                     CheckerContext &C,
                                     StringRef Ctx) {
    if (!isTopLevelShiftExpr(WholeExpr, Shl))
      return true;

    if (Ctx == "argument") {
      const CallExpr *CE = nullptr;
      unsigned ArgIdx = 0;
      if (findCallParentAndArgIndex(WholeExpr, C, CE, ArgIdx)) {
        const FunctionDecl *FD = CE->getDirectCallee();
        const ParmVarDecl *PVD = nullptr;
        if (FD && ArgIdx < FD->getNumParams())
          PVD = FD->getParamDecl(ArgIdx);

        if (isAnyLongType(DestTy))
          return true;

        if (PVD && paramNameLooksLikeAddrOffset(PVD))
          return true;

        if (FD) {
          if (const IdentifierInfo *ID = FD->getIdentifier()) {
            if (calleeNameLooksLikeIOOrReg(ID->getName()))
              return true;
          }
        }

        uint64_t K = 0;
        if (tryGetConstShiftAmount(Shl->getRHS(), C, K) && K <= 3)
          return true;
      }
    }

    return false;
  }

  // Extract a coarse upper bound from an assignment RHS by scanning integer literals.
  static bool extractUpperBoundLiteralFromRHS(const Expr *RHS, CheckerContext &C,
                                              llvm::APSInt &Out) {
    if (!RHS)
      return false;

    // Walk the subtree, find the maximum integer literal value.
    llvm::APSInt MaxVal(64, true); // unsigned
    bool Found = false;

    llvm::SmallVector<const Stmt *, 16> Worklist;
    Worklist.push_back(RHS);
    while (!Worklist.empty()) {
      const Stmt *Cur = Worklist.pop_back_val();
      if (!Cur) continue;

      if (const auto *IL = dyn_cast<IntegerLiteral>(Cur)) {
        llvm::APInt V = IL->getValue();
        if (!Found || V.ugt(MaxVal))
          MaxVal = llvm::APSInt(V, /*isUnsigned=*/true);
        Found = true;
      } else if (const auto *CharL = dyn_cast<CharacterLiteral>(Cur)) {
        llvm::APInt V(64, CharL->getValue());
        if (!Found || V.ugt(MaxVal))
          MaxVal = llvm::APSInt(V, /*isUnsigned=*/true);
        Found = true;
      } else if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
        if (const Expr *SubE = UO->getSubExpr())
          Worklist.push_back(SubE);
      } else {
        for (const Stmt *Child : Cur->children())
          if (Child)
            Worklist.push_back(Child);
      }
    }

    if (Found) {
      Out = MaxVal;
      return true;
    }
    return false;
  }

  // Exact constant for variables from program state
  static bool getRecordedVarExactConst(const Expr *E, CheckerContext &C,
                                       llvm::APSInt &Out) {
    const auto *DRE = dyn_cast_or_null<DeclRefExpr>(peel(E));
    if (!DRE)
      return false;
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;

    ProgramStateRef State = C.getState();
    const llvm::APSInt *Stored = State->get<VarConstMap>(VD);
    if (!Stored)
      return false;
    Out = *Stored;
    return true;
  }

  static bool getRecordedVarUpperBound(const Expr *E, CheckerContext &C,
                                       llvm::APSInt &Out) {
    const auto *DRE = dyn_cast_or_null<DeclRefExpr>(peel(E));
    if (!DRE)
      return false;
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;

    ProgramStateRef State = C.getState();
    const llvm::APSInt *Stored = State->get<VarUpperBoundMap>(VD);
    if (!Stored)
      return false;
    Out = *Stored;
    return true;
  }

  enum UpperBoundOrigin {
    UBO_None = 0,
    UBO_Const = 1,
    UBO_ExactVar = 2,
    UBO_FromState = 4,
    UBO_FromVarUB = 8,
    UBO_FromExpr = 16
  };

  static bool tryEvalConstOrRecorded(const Expr *E, CheckerContext &C,
                                     llvm::APSInt &Out, UpperBoundOrigin &Origin) {
    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, E, C)) {
      Out = Val;
      Origin = UBO_Const;
      return true;
    }
    if (getRecordedVarExactConst(E, C, Val)) {
      Out = Val;
      Origin = UBO_ExactVar;
      return true;
    }
    return false;
  }

  // Helper: bitfield info for MemberExpr
  static bool getBitfieldInfo(const Expr *E, CheckerContext &C,
                              unsigned &Width, bool &IsUnsigned) {
    E = peel(E);
    const auto *ME = dyn_cast_or_null<MemberExpr>(E);
    if (!ME)
      return false;
    const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD || !FD->isBitField())
      return false;
    Width = FD->getBitWidthValue(C.getASTContext());
    IsUnsigned = FD->getType()->isUnsignedIntegerType();
    return true;
  }

  // Compute an upper bound for an expression. Also report where it comes from.
  static bool computeExprUpperBoundEx(const Expr *E, CheckerContext &C,
                                      llvm::APSInt &Out, UpperBoundOrigin &Origin) {
    if (!E)
      return false;
    E = peel(E);

    // Constants or recorded exact values
    if (tryEvalConstOrRecorded(E, C, Out, Origin)) {
      if (Out.isSigned() && Out.isNegative())
        return false;
      Out = Out.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }

    // Bitfield member expression: compute UB from declared width.
    unsigned BFWidth = 0;
    bool BFUnsigned = false;
    if (getBitfieldInfo(E, C, BFWidth, BFUnsigned)) {
      unsigned EffWidth = BFUnsigned ? BFWidth : (BFWidth ? BFWidth - 1 : 0);
      llvm::APInt MaxVal(64, 0);
      if (EffWidth > 0) {
        llvm::APInt Ones = llvm::APInt::getMaxValue(EffWidth);
        MaxVal = Ones.zextOrTrunc(64);
      }
      Out = llvm::APSInt(MaxVal, /*isUnsigned=*/true);
      Origin = UBO_FromExpr;
      return true;
    }

    // Variable with recorded coarse upper bound?
    if (getRecordedVarUpperBound(E, C, Out)) {
      Origin = UBO_FromVarUB;
      Out = Out.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }

    // Symbolic? Try constraint manager max.
    ProgramStateRef State = C.getState();
    SVal SV = State->getSVal(E, C.getLocationContext());
    if (std::optional<nonloc::ConcreteInt> CI = SV.getAs<nonloc::ConcreteInt>()) {
      llvm::APSInt CIVal = CI->getValue();
      if (CIVal.isSigned() && CIVal.isNegative())
        return false;
      Out = CIVal.extOrTrunc(64);
      Out.setIsUnsigned(true);
      Origin = UBO_Const;
      return true;
    }
    if (SymbolRef Sym = SV.getAsSymbol()) {
      if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
        llvm::APSInt M = *Max;
        if (M.isSigned() && M.isNegative())
          return false;
        Out = M.extOrTrunc(64);
        Out.setIsUnsigned(true);
        Origin = UBO_FromState;
        return true;
      }
    }

    // Structural handling
    if (const auto *CE = dyn_cast<CastExpr>(E)) {
      llvm::APSInt SubUB;
      UpperBoundOrigin SubO = UBO_None;
      if (computeExprUpperBoundEx(CE->getSubExpr(), C, SubUB, SubO)) {
        Out = SubUB;
        Origin = (UpperBoundOrigin)(SubO | UBO_FromExpr);
        return true;
      }
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      llvm::APSInt TUB, FUB;
      UpperBoundOrigin TO = UBO_None, FO = UBO_None;
      bool THave = computeExprUpperBoundEx(CO->getTrueExpr(), C, TUB, TO);
      bool FHave = computeExprUpperBoundEx(CO->getFalseExpr(), C, FUB, FO);
      if (THave && FHave) {
        unsigned BW = std::max(TUB.getBitWidth(), FUB.getBitWidth());
        llvm::APSInt T2 = TUB.extOrTrunc(BW);
        llvm::APSInt F2 = FUB.extOrTrunc(BW);
        T2.setIsUnsigned(true);
        F2.setIsUnsigned(true);
        Out = (T2 > F2) ? T2 : F2;
        Origin = (UpperBoundOrigin)(TO | FO | UBO_FromExpr);
        return true;
      }
      if (THave) {
        Out = TUB;
        Origin = (UpperBoundOrigin)(TO | UBO_FromExpr);
        return true;
      }
      if (FHave) {
        Out = FUB;
        Origin = (UpperBoundOrigin)(FO | UBO_FromExpr);
        return true;
      }
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      llvm::APSInt LUB, RUB;
      UpperBoundOrigin LO = UBO_None, RO = UBO_None;

      auto combineUBits = [&](llvm::APSInt &A, llvm::APSInt &B) -> unsigned {
        llvm::APSInt A2 = A.extOrTrunc(64); A2.setIsUnsigned(true);
        llvm::APSInt B2 = B.extOrTrunc(64); B2.setIsUnsigned(true);
        return std::max(A2.getBitWidth(), B2.getBitWidth());
      };

      switch (BO->getOpcode()) {
      case BO_Add:
      case BO_Sub:
      case BO_Mul:
      case BO_Div:
      case BO_Rem:
        // Fallback: try generic UB on both sides, add for Add/Sub as a safe over-approx.
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO) &&
            computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO)) {
          unsigned BW = std::max(LUB.getBitWidth(), RUB.getBitWidth());
          llvm::APSInt L2 = LUB.extOrTrunc(BW); L2.setIsUnsigned(true);
          llvm::APSInt R2 = RUB.extOrTrunc(BW); R2.setIsUnsigned(true);
          if (BO->getOpcode() == BO_Add || BO->getOpcode() == BO_Sub) {
            Out = L2 + R2; // Safe upper bound
          } else if (BO->getOpcode() == BO_Mul) {
            llvm::APInt Tmp = static_cast<const llvm::APInt &>(L2);
            Tmp = Tmp.zextOrTrunc(64);
            Tmp = Tmp * static_cast<const llvm::APInt &>(R2);
            Out = llvm::APSInt(Tmp, true);
          } else {
            // For Div/Rem, upper bound cannot exceed LHS upper bound.
            Out = L2;
          }
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        break;

      case BO_Or:
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO) &&
            computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO)) {
          llvm::APInt LA = static_cast<const llvm::APInt &>(LUB.extOrTrunc(64));
          llvm::APInt RA = static_cast<const llvm::APInt &>(RUB.extOrTrunc(64));
          Out = llvm::APSInt(LA | RA, true);
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        break;

      case BO_Xor:
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO) &&
            computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO)) {
          llvm::APInt LA = static_cast<const llvm::APInt &>(LUB.extOrTrunc(64));
          llvm::APInt RA = static_cast<const llvm::APInt &>(RUB.extOrTrunc(64));
          // Upper bound of XOR is safely bounded by OR of UB's.
          Out = llvm::APSInt(LA | RA, true);
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        break;

      case BO_And: {
        bool LH = computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO);
        bool RH = computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO);
        if (LH && RH) {
          // A & B <= min(UB(A), UB(B))
          llvm::APSInt L2 = LUB.extOrTrunc(64); L2.setIsUnsigned(true);
          llvm::APSInt R2 = RUB.extOrTrunc(64); R2.setIsUnsigned(true);
          Out = (L2 < R2) ? L2 : R2;
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        // Better: if one side is constant, result UB is <= that constant
        llvm::APSInt ConstSide;
        UpperBoundOrigin OO = UBO_None;
        if (tryEvalConstOrRecorded(BO->getLHS(), C, ConstSide, OO)) {
          Out = ConstSide.extOrTrunc(64);
          Out.setIsUnsigned(true);
          Origin = (UpperBoundOrigin)(OO | UBO_FromExpr);
          return true;
        }
        if (tryEvalConstOrRecorded(BO->getRHS(), C, ConstSide, OO)) {
          Out = ConstSide.extOrTrunc(64);
          Out.setIsUnsigned(true);
          Origin = (UpperBoundOrigin)(OO | UBO_FromExpr);
          return true;
        }
        break;
      }

      case BO_Shl: {
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO) &&
            computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO)) {
          uint64_t Sh = RUB.getZExtValue();
          Sh = std::min<uint64_t>(Sh, 63);
          llvm::APSInt L2 = LUB.extOrTrunc(64);
          L2.setIsUnsigned(true);
          llvm::APInt Tmp = static_cast<const llvm::APInt &>(L2);
          Tmp = Tmp.shl((unsigned)Sh);
          Out = llvm::APSInt(Tmp, true);
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        break;
      }

      case BO_Shr: {
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO)) {
          // Use smallest shift (best-case for maximizing the result).
          llvm::APSInt ShiftC;
          UpperBoundOrigin SO = UBO_None;
          uint64_t MinShift = 0;
          if (tryEvalConstOrRecorded(BO->getRHS(), C, ShiftC, SO)) {
            MinShift = std::min<uint64_t>(ShiftC.getZExtValue(), 63);
          } else {
            // If we can get an upper bound for shift, min is 0.
            // So UB(result) <= UB(LHS)
            MinShift = 0;
          }
          llvm::APSInt L2 = LUB.extOrTrunc(64);
          L2.setIsUnsigned(true);
          llvm::APInt Tmp = static_cast<const llvm::APInt &>(L2);
          if (MinShift > 0)
            Tmp = Tmp.lshr((unsigned)MinShift);
          Out = llvm::APSInt(Tmp, true);
          Origin = (UpperBoundOrigin)(LO | UBO_FromExpr);
          return true;
        }
        break;
      }

      default:
        break;
      }
    }

    return false;
  }

  static bool computeExprUpperBound(const Expr *E, CheckerContext &C,
                                    llvm::APSInt &Out) {
    UpperBoundOrigin Ign = UBO_None;
    return computeExprUpperBoundEx(E, C, Out, Ign);
  }

  // Compute maximum number of active bits an expression's value can have.
  static bool computeExprMaxActiveBits(const Expr *E, CheckerContext &C,
                                       unsigned &OutBits) {
    if (!E)
      return false;
    E = peel(E);

    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, E, C)) {
      if (Val.isSigned() && Val.isNegative())
        return false;
      OutBits = Val.getActiveBits();
      return true;
    }

    // Bitfield exact bound
    unsigned BFWidth = 0;
    bool BFUnsigned = false;
    if (getBitfieldInfo(E, C, BFWidth, BFUnsigned)) {
      OutBits = BFUnsigned ? BFWidth : (BFWidth ? BFWidth - 1 : 0);
      return true;
    }

    llvm::APSInt UB;
    if (computeExprUpperBound(E, C, UB)) {
      OutBits = UB.getActiveBits();
      return true;
    }

    return false;
  }

  // Lightweight "forced-one" bits mask for an expression (64-bit).
  static llvm::APInt computeForcedOneMask(const Expr *E, CheckerContext &C) {
    E = peel(E);
    llvm::APInt Zero(64, 0);

    if (!E)
      return Zero;

    // Integer constant
    if (const auto *IL = dyn_cast<IntegerLiteral>(E))
      return IL->getValue().zextOrTrunc(64);

    // Exact variable constant
    llvm::APSInt Exact;
    if (getRecordedVarExactConst(E, C, Exact)) {
      llvm::APSInt E2 = Exact.extOrTrunc(64);
      E2.setIsUnsigned(true);
      return static_cast<const llvm::APInt &>(E2);
    }

    // Bitfield: unknown forced-one mask; return zeros (conservative).
    unsigned BFWidth = 0; bool BFUnsigned = false;
    if (getBitfieldInfo(E, C, BFWidth, BFUnsigned)) {
      return Zero;
    }

    // Implicit/explicit casts, parens
    if (const auto *CE = dyn_cast<CastExpr>(E))
      return computeForcedOneMask(CE->getSubExpr(), C);

    if (const auto *PE = dyn_cast<ParenExpr>(E))
      return computeForcedOneMask(PE->getSubExpr(), C);

    // Binary ops
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      switch (BO->getOpcode()) {
      case BO_Or: {
        llvm::APInt LMask = computeForcedOneMask(BO->getLHS(), C);
        llvm::APInt RMask = computeForcedOneMask(BO->getRHS(), C);
        return LMask | RMask;
      }
      case BO_Shl: {
        llvm::APInt LMask = computeForcedOneMask(BO->getLHS(), C);
        // Need exact shift amount
        llvm::APSInt ShAmt;
        if (EvaluateExprToInt(ShAmt, BO->getRHS(), C) ||
            getRecordedVarExactConst(BO->getRHS(), C, ShAmt)) {
          uint64_t K = ShAmt.getZExtValue();
          if (K >= 64)
            return Zero;
          return LMask.shl((unsigned)K);
        }
        return Zero;
      }
      case BO_And: {
        llvm::APInt LMask = computeForcedOneMask(BO->getLHS(), C);
        llvm::APSInt RConst;
        if (EvaluateExprToInt(RConst, BO->getRHS(), C) ||
            getRecordedVarExactConst(BO->getRHS(), C, RConst)) {
          llvm::APSInt RC2 = RConst.extOrTrunc(64);
          RC2.setIsUnsigned(true);
          llvm::APInt RMask = static_cast<const llvm::APInt &>(RC2);
          return LMask & RMask;
        }
        return Zero;
      }
      default:
        break;
      }
    }

    return Zero;
  }

  // Decide if the shift is provably safe within the operation width (e.g., 32-bit)
  // under computed upper bounds for L and R.
  static bool shiftSafeUnderUpperBounds(const Expr *L, const Expr *R,
                                        unsigned OpW, CheckerContext &C) {
    unsigned MaxLBits = 0;
    if (!computeExprMaxActiveBits(L, C, MaxLBits))
      return false;

    llvm::APSInt RMax;
    if (!computeExprUpperBound(R, C, RMax))
      return false;

    uint64_t ShiftMax = RMax.getZExtValue();

    if (MaxLBits == 0)
      return true;

    return (uint64_t)MaxLBits + ShiftMax <= (uint64_t)OpW;
  }

  // Small-constant-shift FP filter: suppress when RHS is a tiny constant (<= 5)
  // and we cannot prove risk from L.
  static bool smallConstantShiftBenign(const Expr *L, const Expr *R,
                                       unsigned OpW, CheckerContext &C) {
    llvm::APSInt RC;
    if (!(EvaluateExprToInt(RC, R, C)))
      return false;
    uint64_t K = RC.getZExtValue();
    const uint64_t SmallKThreshold = 5;
    if (K > SmallKThreshold)
      return false;

    // If L is constant, check exactly.
    llvm::APSInt LC;
    if (EvaluateExprToInt(LC, L, C)) {
      if (LC.isSigned() && LC.isNegative())
        return false;
      unsigned LBits = LC.getActiveBits();
      return (uint64_t)LBits + K <= (uint64_t)OpW;
    }

    // Special-case: L is an unsigned bitfield of width W: check W + K
    unsigned BFWidth = 0; bool BFUnsigned = false;
    if (getBitfieldInfo(L, C, BFWidth, BFUnsigned) && BFUnsigned) {
      return (uint64_t)BFWidth + K <= (uint64_t)OpW;
    }

    // Use forced-one bits to get a lower bound on L's active bits.
    llvm::APInt Forced = computeForcedOneMask(L, C);
    unsigned MinLBits = Forced.getActiveBits();
    if (MinLBits == 0) {
      // With no evidence of large L, treat tiny shifts as benign to reduce FP.
      return true;
    }
    // If even the minimum L would overflow with K, do not suppress.
    return (uint64_t)MinLBits + K <= (uint64_t)OpW;
  }

  // Targeted FP filter: if L is an unsigned bitfield of width W and RHS is a
  // constant K such that W + K <= OpW, the shift is safe in 32-bit.
  static bool bitfieldConstShiftSafe(const Expr *L, const Expr *R,
                                     unsigned OpW, CheckerContext &C) {
    unsigned W = 0; bool IsU = false;
    if (!getBitfieldInfo(L, C, W, IsU) || !IsU)
      return false;
    llvm::APSInt RC;
    if (!EvaluateExprToInt(RC, R, C))
      return false;
    uint64_t K = RC.getZExtValue();
    return (uint64_t)W + K <= (uint64_t)OpW;
  }

  static bool isFunctionParamExpr(const Expr *E) {
    const auto *DRE = dyn_cast_or_null<DeclRefExpr>(peel(E));
    if (!DRE)
      return false;
    return isa<ParmVarDecl>(DRE->getDecl());
  }

  static bool isSmallLiteralLE(const Expr *E, unsigned Limit, CheckerContext &C, uint64_t &ValOut) {
    llvm::APSInt LC;
    if (!EvaluateExprToInt(LC, E, C))
      return false;
    if (LC.isSigned() && LC.isNegative())
      return false;
    uint64_t V = LC.getZExtValue();
    if (V <= Limit) {
      ValOut = V;
      return true;
    }
    return false;
  }

  // Update VarConstMap for exact constant assignment
  static ProgramStateRef setOrClearVarConst(ProgramStateRef State,
                                            const VarDecl *VD,
                                            const Expr *RHS,
                                            CheckerContext &C) {
    llvm::APSInt Exact;
    if (EvaluateExprToInt(Exact, RHS, C)) {
      return State->set<VarConstMap>(VD, Exact);
    }
    // Not a constant: clear any existing entry.
    return State->remove<VarConstMap>(VD);
  }
};

const BinaryOperator *SAGenTestChecker::findShiftInTree(const Stmt *S) {
  if (!S)
    return nullptr;

  if (const BinaryOperator *B = asShift(S))
    return B;

  for (const Stmt *Child : S->children()) {
    if (const BinaryOperator *Res = findShiftInTree(Child))
      return Res;
  }
  return nullptr;
}

bool SAGenTestChecker::hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx) {
  if (!E)
    return false;

  if (const auto *ECE = dyn_cast<ExplicitCastExpr>(E->IgnoreParens())) {
    QualType ToTy = ECE->getType();
    if (ToTy->isIntegerType() && ACtx.getIntWidth(ToTy) >= 64)
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (!Child)
      continue;
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (hasExplicitCastToWide64(CE, ACtx))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                                   CheckerContext &C, StringRef Ctx) const {
  if (!E)
    return;

  ASTContext &ACtx = C.getASTContext();

  if (!DestTy->isIntegerType())
    return;

  unsigned DestW = ACtx.getIntWidth(DestTy);
  if (DestW < 64)
    return;

  const BinaryOperator *Shl = findShiftInTree(E);
  if (!Shl || Shl->getOpcode() != BO_Shl)
    return;

  const Expr *L = Shl->getLHS();
  const Expr *R = Shl->getRHS();
  if (!L || !R)
    return;

  QualType ShlTy = Shl->getType();
  if (!ShlTy->isIntegerType())
    return;

  // Width of the shift expression after usual promotions.
  unsigned OpW = ACtx.getIntWidth(ShlTy);
  if (OpW >= 64)
    return; // Shift already performed in 64-bit, OK.

  if (!L->getType()->isIntegerType())
    return;

  if (hasExplicitCastToWide64(L, ACtx))
    return;

  if (isFalsePositiveContext(E, Shl, DestTy, C, Ctx))
    return;

  // If L and R are constants and fit within OpW, suppress.
  if (constantShiftFitsInWidth(L, R, OpW, C))
    return;

  // FP filter: L is an unsigned bitfield and RHS is a constant; if bounded within OpW, suppress.
  if (bitfieldConstShiftSafe(L, R, OpW, C))
    return;

  // Compute provable risk using upper bounds.
  // 1) Compute maximum active bits for L.
  unsigned MaxLBits = 0;
  bool HaveLBits = computeExprMaxActiveBits(L, C, MaxLBits);

  // 2) Compute an upper bound for shift amount and its origin.
  llvm::APSInt RMax;
  UpperBoundOrigin ROrigin = UBO_None;
  bool HaveRMax = computeExprUpperBoundEx(R, C, RMax, ROrigin);

  // Additional FP filter: if the only knowledge about RHS is the generic
  // "shift less than OpW" constraint (common for preventing UB), and LHS is a tiny
  // literal (<= 8) and RHS is a function parameter, treat as benign.
  if (HaveRMax && ROrigin == UBO_FromState && RMax.getZExtValue() == (OpW - 1)) {
    uint64_t TinyV = 0;
    if (isFunctionParamExpr(R) && isSmallLiteralLE(L, 8, C, TinyV)) {
      return; // suppress this likely benign test pattern, e.g., 3 << order
    }
  }

  // If we can prove it's safe under upper bounds, suppress.
  if (HaveLBits && HaveRMax) {
    uint64_t ShiftMax = RMax.getZExtValue();
    if (MaxLBits == 0 || (uint64_t)MaxLBits + ShiftMax <= (uint64_t)OpW)
      return;
  } else {
    // If we cannot prove risk (lack of bounds), be conservative and do not warn.
    // This avoids FPs where shift amount is effectively bounded but not modeled.
    return;
  }

  // Suppress tiny constant shifts unless we can prove risk.
  if (smallConstantShiftBenign(L, R, OpW, C))
    return;

  // Report
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT, "Shift done in 32-bit, widened after; cast left operand to 64-bit before <<", N);
  Rpt->addRange(Shl->getSourceRange());
  C.emitReport(std::move(Rpt));
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (VD->hasInit()) {
      QualType DestTy = VD->getType();
      const Expr *Init = VD->getInit();
      analyzeAndReportShiftToWide(Init, DestTy, C, "initialization");

      // Update VarConstMap if initializer is a constant.
      ProgramStateRef State = C.getState();
      ProgramStateRef NewState = setOrClearVarConst(State, VD, Init, C);

      // Also maintain coarse upper bound map
      llvm::APSInt BoundLit;
      if (extractUpperBoundLiteralFromRHS(Init, C, BoundLit)) {
        const llvm::APSInt *Cur = State->get<VarUpperBoundMap>(VD);
        llvm::APSInt NewBound = BoundLit;
        if (Cur && Cur->ugt(NewBound))
          NewBound = *Cur;
        NewState = NewState->set<VarUpperBoundMap>(VD, NewBound);
      }

      if (NewState != State)
        C.addTransition(NewState);
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  // First, perform shift-to-wide analysis for assignment context.
  QualType DestTy = LHS->getType();
  analyzeAndReportShiftToWide(RHS, DestTy, C, "assignment");

  // Update per-variable maps.
  const auto *DRE = dyn_cast<DeclRefExpr>(peel(LHS));
  if (!DRE)
    return;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  ProgramStateRef State = C.getState();
  ProgramStateRef NewState = setOrClearVarConst(State, VD, RHS, C);

  llvm::APSInt BoundLit;
  if (extractUpperBoundLiteralFromRHS(RHS, C, BoundLit)) {
    const llvm::APSInt *Cur = NewState->get<VarUpperBoundMap>(VD);
    llvm::APSInt NewBound = BoundLit;
    if (Cur && Cur->ugt(NewBound))
      NewBound = *Cur;
    NewState = NewState->set<VarUpperBoundMap>(VD, NewBound);
  }

  if (NewState != State)
    C.addTransition(NewState);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;
  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  const StackFrameContext *SFC = C.getStackFrame();
  if (!SFC)
    return;
  const auto *FD = dyn_cast_or_null<FunctionDecl>(SFC->getDecl());
  if (!FD)
    return;

  QualType DestTy = FD->getReturnType();
  analyzeAndReportShiftToWide(RetE, DestTy, C, "return");
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  unsigned NumArgs = Call.getNumArgs();
  unsigned NumParams = FD->getNumParams();
  unsigned N = std::min(NumArgs, NumParams);

  for (unsigned i = 0; i < N; ++i) {
    const ParmVarDecl *P = FD->getParamDecl(i);
    if (!P)
      continue;

    QualType DestTy = P->getType();
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    ASTContext &ACtx = C.getASTContext();
    if (!DestTy->isIntegerType() || ACtx.getIntWidth(DestTy) < 64)
      continue;

    analyzeAndReportShiftToWide(ArgE, DestTy, C, "argument");
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects 32-bit left shift widened to 64-bit after the shift (cast should be before <<)",
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
