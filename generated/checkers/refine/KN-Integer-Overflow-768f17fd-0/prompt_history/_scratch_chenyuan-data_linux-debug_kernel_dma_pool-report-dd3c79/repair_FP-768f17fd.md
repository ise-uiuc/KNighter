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

File:| /scratch/chenyuan-data/linux-debug/kernel/dma/pool.c
---|---
Warning:| line 91, column 13
Shift done in 32-bit, widened after; cast left operand to 64-bit before <<

### Annotated Source Code


29    | static int __init early_coherent_pool(char *p)
30    | {
31    | 	atomic_pool_size = memparse(p, &p);
32    |  return 0;
33    | }
34    | early_param("coherent_pool", early_coherent_pool);
35    |
36    | static void __init dma_atomic_pool_debugfs_init(void)
37    | {
38    |  struct dentry *root;
39    |
40    | 	root = debugfs_create_dir("dma_pools", NULL);
41    | 	debugfs_create_ulong("pool_size_dma", 0400, root, &pool_size_dma);
42    | 	debugfs_create_ulong("pool_size_dma32", 0400, root, &pool_size_dma32);
43    | 	debugfs_create_ulong("pool_size_kernel", 0400, root, &pool_size_kernel);
44    | }
45    |
46    | static void dma_atomic_pool_size_add(gfp_t gfp, size_t size)
47    | {
48    |  if (gfp & __GFP_DMA)
49    | 		pool_size_dma += size;
50    |  else if (gfp & __GFP_DMA32)
51    | 		pool_size_dma32 += size;
52    |  else
53    | 		pool_size_kernel += size;
54    | }
55    |
56    | static bool cma_in_zone(gfp_t gfp)
57    | {
58    |  unsigned long size;
59    | 	phys_addr_t end;
60    |  struct cma *cma;
61    |
62    | 	cma = dev_get_cma_area(NULL);
63    |  if (!cma)
64    |  return false;
65    |
66    | 	size = cma_get_size(cma);
67    |  if (!size)
68    |  return false;
69    |
70    |  /* CMA can't cross zone boundaries, see cma_activate_area() */
71    | 	end = cma_get_base(cma) + size - 1;
72    |  if (IS_ENABLED(CONFIG_ZONE_DMA) && (gfp & GFP_DMA))
73    |  return end <= DMA_BIT_MASK(zone_dma_bits);
74    |  if (IS_ENABLED(CONFIG_ZONE_DMA32) && (gfp & GFP_DMA32))
75    |  return end <= DMA_BIT_MASK(32);
76    |  return true;
77    | }
78    |
79    | static int atomic_pool_expand(struct gen_pool *pool, size_t pool_size,
80    | 			      gfp_t gfp)
81    | {
82    |  unsigned int order;
83    |  struct page *page = NULL;
84    |  void *addr;
85    |  int ret = -ENOMEM;
86    |
87    |  /* Cannot allocate larger than MAX_PAGE_ORDER */
88    |  order = min(get_order(pool_size), MAX_PAGE_ORDER);
    9←Assuming '__UNIQUE_ID___x1046' is >= '__UNIQUE_ID___y1047'→
    10←'?' condition is false→
89    |
90    |  do {
91    |  pool_size = 1 << (PAGE_SHIFT + order);
    11←Shift done in 32-bit, widened after; cast left operand to 64-bit before <<
92    |  if (cma_in_zone(gfp))
93    | 			page = dma_alloc_from_contiguous(NULL, 1 << order,
94    | 							 order, false);
95    |  if (!page)
96    | 			page = alloc_pages(gfp, order);
97    | 	} while (!page && order-- > 0);
98    |  if (!page)
99    |  goto out;
100   |
101   | 	arch_dma_prep_coherent(page, pool_size);
102   |
103   | #ifdef CONFIG_DMA_DIRECT_REMAP
104   | 	addr = dma_common_contiguous_remap(page, pool_size,
105   |  pgprot_dmacoherent(PAGE_KERNEL),
106   | 					   __builtin_return_address(0));
107   |  if (!addr)
108   |  goto free_page;
109   | #else
110   | 	addr = page_to_virt(page);
111   | #endif
112   |  /*
113   |  * Memory in the atomic DMA pools must be unencrypted, the pools do not
114   |  * shrink so no re-encryption occurs in dma_direct_free().
115   |  */
116   | 	ret = set_memory_decrypted((unsigned long)page_to_virt(page),
117   | 				   1 << order);
118   |  if (ret)
119   |  goto remove_mapping;
120   | 	ret = gen_pool_add_virt(pool, (unsigned long)addr, page_to_phys(page),
121   | 				pool_size, NUMA_NO_NODE);
122   |  if (ret)
123   |  goto encrypt_mapping;
124   |
125   | 	dma_atomic_pool_size_add(gfp, pool_size);
126   |  return 0;
127   |
128   | encrypt_mapping:
129   | 	ret = set_memory_encrypted((unsigned long)page_to_virt(page),
130   | 				   1 << order);
131   |  if (WARN_ON_ONCE(ret)) {
132   |  /* Decrypt succeeded but encrypt failed, purposely leak */
133   |  goto out;
134   | 	}
135   | remove_mapping:
136   | #ifdef CONFIG_DMA_DIRECT_REMAP
137   | 	dma_common_free_remap(addr, pool_size);
138   | free_page:
139   | 	__free_pages(page, order);
140   | #endif
141   | out:
142   |  return ret;
143   | }
144   |
145   | static void atomic_pool_resize(struct gen_pool *pool, gfp_t gfp)
146   | {
147   |  if (pool && gen_pool_avail(pool) < atomic_pool_size)
148   | 		atomic_pool_expand(pool, gen_pool_size(pool), gfp);
149   | }
150   |
151   | static void atomic_pool_work_fn(struct work_struct *work)
152   | {
153   |  if (IS_ENABLED(CONFIG_ZONE_DMA))
154   | 		atomic_pool_resize(atomic_pool_dma,
155   |  GFP_KERNEL | GFP_DMA);
156   |  if (IS_ENABLED(CONFIG_ZONE_DMA32))
157   | 		atomic_pool_resize(atomic_pool_dma32,
158   |  GFP_KERNEL | GFP_DMA32);
159   | 	atomic_pool_resize(atomic_pool_kernel, GFP_KERNEL);
160   | }
161   |
162   | static __init struct gen_pool *__dma_atomic_pool_init(size_t pool_size,
163   | 						      gfp_t gfp)
164   | {
165   |  struct gen_pool *pool;
166   |  int ret;
167   |
168   | 	pool = gen_pool_create(PAGE_SHIFT, NUMA_NO_NODE);
169   |  if (!pool)
    6←Assuming 'pool' is non-null→
    7←Taking false branch→
170   |  return NULL;
171   |
172   |  gen_pool_set_algo(pool, gen_pool_first_fit_order_align, NULL);
173   |
174   |  ret = atomic_pool_expand(pool, pool_size, gfp);
    8←Calling 'atomic_pool_expand'→
175   |  if (ret) {
176   | 		gen_pool_destroy(pool);
177   |  pr_err("DMA: failed to allocate %zu KiB %pGg pool for atomic allocation\n",
178   |  pool_size >> 10, &gfp);
179   |  return NULL;
180   | 	}
181   |
182   |  pr_info("DMA: preallocated %zu KiB %pGg pool for atomic allocations\n",
183   |  gen_pool_size(pool) >> 10, &gfp);
184   |  return pool;
185   | }
186   |
187   | static int __init dma_atomic_pool_init(void)
188   | {
189   |  int ret = 0;
190   |
191   |  /*
192   |  * If coherent_pool was not used on the command line, default the pool
193   |  * sizes to 128KB per 1GB of memory, min 128KB, max MAX_PAGE_ORDER.
194   |  */
195   |  if (!atomic_pool_size) {
    1Assuming 'atomic_pool_size' is not equal to 0→
    2←Taking false branch→
196   |  unsigned long pages = totalram_pages() / (SZ_1G / SZ_128K);
197   | 		pages = min_t(unsigned long, pages, MAX_ORDER_NR_PAGES);
198   | 		atomic_pool_size = max_t(size_t, pages << PAGE_SHIFT, SZ_128K);
199   | 	}
200   |  INIT_WORK(&atomic_pool_work, atomic_pool_work_fn);
    3←Loop condition is false.  Exiting loop→
    4←Loop condition is false.  Exiting loop→
201   |
202   |  atomic_pool_kernel = __dma_atomic_pool_init(atomic_pool_size,
    5←Calling '__dma_atomic_pool_init'→
203   |  GFP_KERNEL);
204   |  if (!atomic_pool_kernel)
205   | 		ret = -ENOMEM;
206   |  if (has_managed_dma()) {
207   | 		atomic_pool_dma = __dma_atomic_pool_init(atomic_pool_size,
208   |  GFP_KERNEL | GFP_DMA);
209   |  if (!atomic_pool_dma)
210   | 			ret = -ENOMEM;
211   | 	}
212   |  if (IS_ENABLED(CONFIG_ZONE_DMA32)) {
213   | 		atomic_pool_dma32 = __dma_atomic_pool_init(atomic_pool_size,
214   |  GFP_KERNEL | GFP_DMA32);
215   |  if (!atomic_pool_dma32)
216   | 			ret = -ENOMEM;
217   | 	}
218   |
219   | 	dma_atomic_pool_debugfs_init();
220   |  return ret;
221   | }
222   | postcore_initcall(dma_atomic_pool_init);
223   |
224   | static inline struct gen_pool *dma_guess_pool(struct gen_pool *prev, gfp_t gfp)
225   | {
226   |  if (prev == NULL) {
227   |  if (IS_ENABLED(CONFIG_ZONE_DMA32) && (gfp & GFP_DMA32))
228   |  return atomic_pool_dma32;
229   |  if (atomic_pool_dma && (gfp & GFP_DMA))
230   |  return atomic_pool_dma;
231   |  return atomic_pool_kernel;
232   | 	}
233   |  if (prev == atomic_pool_kernel)

Analysis:
- Decision: NotABug
- Reason: The reported line computes pool_size = 1 << (PAGE_SHIFT + order). The left operand is an int literal, so the shift is performed in 32-bit. However:
  - order is bounded: order = min(get_order(pool_size), MAX_PAGE_ORDER). In practice MAX_PAGE_ORDER is small (derived from MAX_ORDER, typically around 10–11 across architectures).
  - PAGE_SHIFT is at most 16 (64K pages).
  - Therefore PAGE_SHIFT + order is well below 31 on real configurations, yielding a value that fits within 32-bit int (e.g., with PAGE_SHIFT=16 and order=10, the result is 1<<26 = 64 MiB).
  - The assignment to size_t (64-bit on 64-bit platforms) does not lose bits; the computed value remains within 32-bit range.
  - This does not match the target bug pattern (a 32-bit shift whose intended result exceeds 32 bits and is only widened after the shift, causing truncation). There is no evidence of overflow/truncation here, and no corresponding kernel fix that casts before the shift.

Given the bounded ranges, the shift result never requires more than 32 bits, so the warning is a false positive relative to the target pattern and not a real bug.

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
#include <algorithm>
#include <cctype>

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

  // Helpers to refine and reduce false positives.
  static const Expr *peel(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  // Report only if the shift is the top-level expression reaching the 64-bit destination.
  static bool isTopLevelShiftExpr(const Expr *ContainerE, const BinaryOperator *Shl) {
    if (!ContainerE || !Shl)
      return false;
    const Expr *Top = peel(ContainerE);
    return Top == static_cast<const Expr *>(Shl);
  }

  // Precise constant-safety check: if both LHS and RHS are constant and the result
  // provably fits into the LHS bitwidth, we suppress.
  static bool constantShiftFitsInLHSWidth(const Expr *L, const Expr *R,
                                          unsigned LHSW, CheckerContext &C) {
    llvm::APSInt LHSEval, RHSEval;
    if (!EvaluateExprToInt(LHSEval, L, C))
      return false;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;

    // Be conservative for negative LHS.
    if (LHSEval.isSigned() && LHSEval.isNegative())
      return false;

    // Active bits of the non-negative LHS.
    unsigned LBits = LHSEval.getActiveBits(); // 0 if value == 0
    uint64_t ShiftAmt = RHSEval.getZExtValue();

    // Safe if highest set bit after shifting still fits in LHS width.
    // LBits == 0 is always safe (0 << n == 0).
    if (LBits == 0)
      return true;

    // Example: a 32-bit LHS can hold results where (LBits + ShiftAmt) <= 32.
    return (uint64_t)LBits + ShiftAmt <= (uint64_t)LHSW;
  }

  // New: return true if type is a "long" (signed or unsigned).
  static bool isAnyLongType(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::Long) ||
           QT->isSpecificBuiltinType(BuiltinType::ULong);
  }

  // New: return true if type is a fixed 64-bit builtin (long long or unsigned long long).
  static bool isFixed64Builtin(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::LongLong) ||
           QT->isSpecificBuiltinType(BuiltinType::ULongLong);
  }

  // New: determine if a function name looks like I/O or register access
  static bool calleeNameLooksLikeIOOrReg(StringRef Name) {
    // Heuristics commonly seen in low-level code: read/write/peek/poke/io/in/out/reg
    // Lowercase for robust matching.
    llvm::SmallString<64> Lower(Name);
    for (char &c : Lower)
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    StringRef S(Lower);
    return S.contains("read") || S.contains("write") || S.contains("peek") ||
           S.contains("poke") || S.contains("in") || S.contains("out") ||
           S.contains("io") || S.contains("reg");
  }

  // New: determine if parameter name suggests address/offset/register
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

  // New: Evaluate RHS constant shift amount if any
  static bool tryGetConstShiftAmount(const Expr *R, CheckerContext &C, uint64_t &Out) {
    llvm::APSInt RHSEval;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;
    Out = RHSEval.getZExtValue();
    return true;
  }

  // Helper: find the CallExpr parent and argument index for an expression E.
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

  // Centralized FP gate. Now with call-argument heuristics.
  static bool isFalsePositiveContext(const Expr *WholeExpr,
                                     const BinaryOperator *Shl,
                                     QualType DestTy,
                                     CheckerContext &C,
                                     StringRef Ctx) {
    // Suppress if the shift isn't the top-level expression being assigned/returned/passed.
    if (!isTopLevelShiftExpr(WholeExpr, Shl))
      return true;

    // Additional filtering only for call-argument contexts.
    if (Ctx == "argument") {
      const CallExpr *CE = nullptr;
      unsigned ArgIdx = 0;
      if (findCallParentAndArgIndex(WholeExpr, C, CE, ArgIdx)) {
        const FunctionDecl *FD = CE->getDirectCallee();
        const ParmVarDecl *PVD = nullptr;
        if (FD && ArgIdx < FD->getNumParams())
          PVD = FD->getParamDecl(ArgIdx);

        // If destination type is a 'long' (LP64 64-bit), suppress: often address/offset.
        if (isAnyLongType(DestTy))
          return true;

        // If parameter name looks like address/offset/register, suppress.
        if (PVD && paramNameLooksLikeAddrOffset(PVD))
          return true;

        // If callee name suggests register/I/O helpers, suppress.
        if (FD) {
          if (const IdentifierInfo *ID = FD->getIdentifier()) {
            if (calleeNameLooksLikeIOOrReg(ID->getName()))
              return true;
          }
        }

        // Small constant shifts (<= 3) in arguments are typically word/byte conversions.
        uint64_t K = 0;
        if (tryGetConstShiftAmount(Shl->getRHS(), C, K) && K <= 3)
          return true;
      }
    }

    return false;
  }
};

static const BinaryOperator *asShift(const Stmt *S) {
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Shl)
      return BO;
  }
  return nullptr;
}

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

  unsigned ShlW = ACtx.getIntWidth(ShlTy);
  if (ShlW >= 64)
    return; // Shift already performed in 64-bit, OK.

  // LHS must be integer and narrower than 64.
  if (!L->getType()->isIntegerType())
    return;

  unsigned LHSW = ACtx.getIntWidth(L->getType());
  if (LHSW >= 64)
    return; // LHS is already wide enough.

  // If there is an explicit cast to >=64-bit within the LHS subtree, suppress.
  if (hasExplicitCastToWide64(L, ACtx))
    return;

  // Suppress known false-positive contexts (not top-level or filtered call-argument cases).
  if (isFalsePositiveContext(E, Shl, DestTy, C, Ctx))
    return;

  // Precise constant-bound suppression: only if both sides are constants and safe.
  if (constantShiftFitsInLHSWidth(L, R, LHSW, C))
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
    if (!VD->hasInit())
      continue;

    QualType DestTy = VD->getType();
    const Expr *Init = VD->getInit();
    analyzeAndReportShiftToWide(Init, DestTy, C, "initialization");
  }
}

void SAGenTestChecker::checkBind(SVal, SVal, const Stmt *S, CheckerContext &C) const {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  QualType DestTy = LHS->getType();
  analyzeAndReportShiftToWide(RHS, DestTy, C, "assignment");
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

    // Only analyze arguments with integer destination types of width >= 64.
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
