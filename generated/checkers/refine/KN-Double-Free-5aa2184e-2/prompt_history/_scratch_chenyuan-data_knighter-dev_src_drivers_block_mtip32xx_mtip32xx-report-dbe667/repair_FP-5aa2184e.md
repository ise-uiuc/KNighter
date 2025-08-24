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

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

The patch that needs to be detected:

## Patch Description

net/mlx5: HWS, fixed double free in error flow of definer layout

Fix error flow bug that could lead to double free of a buffer
during a failure to calculate a suitable definer layout.

Fixes: 74a778b4a63f ("net/mlx5: HWS, added definers handling")
Signed-off-by: Yevgeny Kliteynik <kliteyn@nvidia.com>
Reviewed-by: Itamar Gozlan <igozlan@nvidia.com>
Signed-off-by: Tariq Toukan <tariqt@nvidia.com>
Signed-off-by: Paolo Abeni <pabeni@redhat.com>

## Buggy Code

```c
// Function: mlx5hws_definer_calc_layout in drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
int
mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,
			    struct mlx5hws_match_template *mt,
			    struct mlx5hws_definer *match_definer)
{
	u8 *match_hl;
	int ret;

	/* Union header-layout (hl) is used for creating a single definer
	 * field layout used with different bitmasks for hash and match.
	 */
	match_hl = kzalloc(MLX5_ST_SZ_BYTES(definer_hl), GFP_KERNEL);
	if (!match_hl)
		return -ENOMEM;

	/* Convert all mt items to header layout (hl)
	 * and allocate the match and range field copy array (fc & fcr).
	 */
	ret = hws_definer_conv_match_params_to_hl(ctx, mt, match_hl);
	if (ret) {
		mlx5hws_err(ctx, "Failed to convert items to header layout\n");
		goto free_fc;
	}

	/* Find the match definer layout for header layout match union */
	ret = hws_definer_find_best_match_fit(ctx, match_definer, match_hl);
	if (ret) {
		if (ret == -E2BIG)
			mlx5hws_dbg(ctx,
				    "Failed to create match definer from header layout - E2BIG\n");
		else
			mlx5hws_err(ctx,
				    "Failed to create match definer from header layout (%d)\n",
				    ret);
		goto free_fc;
	}

	kfree(match_hl);
	return 0;

free_fc:
	kfree(mt->fc);

	kfree(match_hl);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
index d566d2ddf424..3f4c58bada37 100644
--- a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
+++ b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
@@ -1925,7 +1925,7 @@ mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,
 	ret = hws_definer_conv_match_params_to_hl(ctx, mt, match_hl);
 	if (ret) {
 		mlx5hws_err(ctx, "Failed to convert items to header layout\n");
-		goto free_fc;
+		goto free_match_hl;
 	}

 	/* Find the match definer layout for header layout match union */
@@ -1946,7 +1946,7 @@ mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,

 free_fc:
 	kfree(mt->fc);
-
+free_match_hl:
 	kfree(match_hl);
 	return ret;
 }
```


# False Positive Report

### Report Summary

File:| drivers/block/mtip32xx/mtip32xx.c
---|---
Warning:| line 2847, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


2283  |  return -1;
2284  | 	}
2285  |
2286  | 	debugfs_create_file("flags", 0444, dd->dfs_node, dd, &mtip_flags_fops);
2287  | 	debugfs_create_file("registers", 0444, dd->dfs_node, dd,
2288  | 			    &mtip_regs_fops);
2289  |
2290  |  return 0;
2291  | }
2292  |
2293  | static void mtip_hw_debugfs_exit(struct driver_data *dd)
2294  | {
2295  |  debugfs_remove_recursive(dd->dfs_node);
2296  | }
2297  |
2298  | /*
2299  |  * Perform any init/resume time hardware setup
2300  |  *
2301  |  * @dd Pointer to the driver data structure.
2302  |  *
2303  |  * return value
2304  |  *	None
2305  |  */
2306  | static inline void hba_setup(struct driver_data *dd)
2307  | {
2308  | 	u32 hwdata;
2309  | 	hwdata = readl(dd->mmio + HOST_HSORG);
2310  |
2311  |  /* interrupt bug workaround: use only 1 IS bit.*/
2312  |  writel(hwdata |
2313  |  HSORG_DISABLE_SLOTGRP_INTR |
2314  |  HSORG_DISABLE_SLOTGRP_PXIS,
2315  | 		dd->mmio + HOST_HSORG);
2316  | }
2317  |
2318  | static int mtip_device_unaligned_constrained(struct driver_data *dd)
2319  | {
2320  |  return (dd->pdev->device == P420M_DEVICE_ID ? 1 : 0);
2321  | }
2322  |
2323  | /*
2324  |  * Detect the details of the product, and store anything needed
2325  |  * into the driver data structure.  This includes product type and
2326  |  * version and number of slot groups.
2327  |  *
2328  |  * @dd Pointer to the driver data structure.
2329  |  *
2330  |  * return value
2331  |  *	None
2332  |  */
2333  | static void mtip_detect_product(struct driver_data *dd)
2334  | {
2335  | 	u32 hwdata;
2336  |  unsigned int rev, slotgroups;
2337  |
2338  |  /*
2339  |  * HBA base + 0xFC [15:0] - vendor-specific hardware interface
2340  |  * info register:
2341  |  * [15:8] hardware/software interface rev#
2342  |  * [   3] asic-style interface
2343  |  * [ 2:0] number of slot groups, minus 1 (only valid for asic-style).
2344  |  */
2345  | 	hwdata = readl(dd->mmio + HOST_HSORG);
2346  |
2347  | 	dd->product_type = MTIP_PRODUCT_UNKNOWN;
2348  | 	dd->slot_groups = 1;
2349  |
2350  |  if (hwdata & 0x8) {
2351  | 		dd->product_type = MTIP_PRODUCT_ASICFPGA;
2352  | 		rev = (hwdata & HSORG_HWREV) >> 8;
2353  | 		slotgroups = (hwdata & HSORG_SLOTGROUPS) + 1;
2354  |  dev_info(&dd->pdev->dev,
2355  |  "ASIC-FPGA design, HS rev 0x%x, "
2356  |  "%i slot groups [%i slots]\n",
2357  |  rev,
2358  |  slotgroups,
2359  |  slotgroups * 32);
2360  |
2361  |  if (slotgroups > MTIP_MAX_SLOT_GROUPS) {
2362  |  dev_warn(&dd->pdev->dev,
2363  |  "Warning: driver only supports "
2364  |  "%i slot groups.\n", MTIP_MAX_SLOT_GROUPS);
2365  | 			slotgroups = MTIP_MAX_SLOT_GROUPS;
2366  | 		}
2367  | 		dd->slot_groups = slotgroups;
2368  |  return;
2369  | 	}
2370  |
2371  |  dev_warn(&dd->pdev->dev, "Unrecognized product id\n");
2372  | }
2373  |
2374  | /*
2375  |  * Blocking wait for FTL rebuild to complete
2376  |  *
2377  |  * @dd Pointer to the DRIVER_DATA structure.
2378  |  *
2379  |  * return value
2380  |  *	0	FTL rebuild completed successfully
2381  |  *	-EFAULT FTL rebuild error/timeout/interruption
2382  |  */
2383  | static int mtip_ftl_rebuild_poll(struct driver_data *dd)
2384  | {
2385  |  unsigned long timeout, cnt = 0, start;
2386  |
2387  |  dev_warn(&dd->pdev->dev,
2388  |  "FTL rebuild in progress. Polling for completion.\n");
2389  |
2390  | 	start = jiffies;
2391  | 	timeout = jiffies + msecs_to_jiffies(MTIP_FTL_REBUILD_TIMEOUT_MS);
2392  |
2393  |  do {
2394  |  if (unlikely(test_bit(MTIP_DDF_REMOVE_PENDING_BIT,
2395  |  &dd->dd_flag)))
2396  |  return -EFAULT;
2397  |  if (mtip_check_surprise_removal(dd))
2398  |  return -EFAULT;
2399  |
2400  |  if (mtip_get_identify(dd->port, NULL) < 0)
2401  |  return -EFAULT;
2663  | 	mtip_dump_identify(dd->port);
2664  |
2665  |  /* check write protect, over temp and rebuild statuses */
2666  | 	rv = mtip_read_log_page(dd->port, ATA_LOG_SATA_NCQ,
2667  | 				dd->port->log_buf,
2668  | 				dd->port->log_buf_dma, 1);
2669  |  if (rv) {
2670  |  dev_warn(&dd->pdev->dev,
2671  |  "Error in READ LOG EXT (10h) command\n");
2672  |  /* non-critical error, don't fail the load */
2673  | 	} else {
2674  | 		buf = (unsigned char *)dd->port->log_buf;
2675  |  if (buf[259] & 0x1) {
2676  |  dev_info(&dd->pdev->dev,
2677  |  "Write protect bit is set.\n");
2678  | 			set_bit(MTIP_DDF_WRITE_PROTECT_BIT, &dd->dd_flag);
2679  | 		}
2680  |  if (buf[288] == 0xF7) {
2681  |  dev_info(&dd->pdev->dev,
2682  |  "Exceeded Tmax, drive in thermal shutdown.\n");
2683  | 			set_bit(MTIP_DDF_OVER_TEMP_BIT, &dd->dd_flag);
2684  | 		}
2685  |  if (buf[288] == 0xBF) {
2686  |  dev_info(&dd->pdev->dev,
2687  |  "Drive indicates rebuild has failed.\n");
2688  | 			set_bit(MTIP_DDF_REBUILD_FAILED_BIT, &dd->dd_flag);
2689  | 		}
2690  | 	}
2691  |
2692  |  /* get write protect progess */
2693  |  memset(&attr242, 0, sizeof(struct smart_attr));
2694  |  if (mtip_get_smart_attr(dd->port, 242, &attr242))
2695  |  dev_warn(&dd->pdev->dev,
2696  |  "Unable to check write protect progress\n");
2697  |  else
2698  |  dev_info(&dd->pdev->dev,
2699  |  "Write protect progress: %u%% (%u blocks)\n",
2700  |  attr242.cur, le32_to_cpu(attr242.data));
2701  |
2702  |  return rv;
2703  | }
2704  |
2705  | /*
2706  |  * Called once for each card.
2707  |  *
2708  |  * @dd Pointer to the driver data structure.
2709  |  *
2710  |  * return value
2711  |  *	0 on success, else an error code.
2712  |  */
2713  | static int mtip_hw_init(struct driver_data *dd)
2714  | {
2715  |  int i;
2716  |  int rv;
2717  |  unsigned long timeout, timetaken;
2718  |
2719  | 	dd->mmio = pcim_iomap_table(dd->pdev)[MTIP_ABAR];
2720  |
2721  | 	mtip_detect_product(dd);
2722  |  if (dd->product_type0.1Field 'product_type' is equal to MTIP_PRODUCT_UNKNOWN == MTIP_PRODUCT_UNKNOWN) {
    1Taking true branch→
2723  |  rv = -EIO;
2724  |  goto out1;
    2←Control jumps to line 2847→
2725  | 	}
2726  |
2727  | 	hba_setup(dd);
2728  |
2729  | 	dd->port = kzalloc_node(sizeof(struct mtip_port), GFP_KERNEL,
2730  | 				dd->numa_node);
2731  |  if (!dd->port)
2732  |  return -ENOMEM;
2733  |
2734  |  /* Continue workqueue setup */
2735  |  for (i = 0; i < MTIP_MAX_SLOT_GROUPS; i++)
2736  | 		dd->work[i].port = dd->port;
2737  |
2738  |  /* Enable unaligned IO constraints for some devices */
2739  |  if (mtip_device_unaligned_constrained(dd))
2740  | 		dd->unal_qdepth = MTIP_MAX_UNALIGNED_SLOTS;
2741  |  else
2742  | 		dd->unal_qdepth = 0;
2743  |
2744  | 	atomic_set(&dd->port->cmd_slot_unal, dd->unal_qdepth);
2745  |
2746  |  /* Spinlock to prevent concurrent issue */
2747  |  for (i = 0; i < MTIP_MAX_SLOT_GROUPS; i++)
2748  |  spin_lock_init(&dd->port->cmd_issue_lock[i]);
2749  |
2750  |  /* Set the port mmio base address. */
2751  | 	dd->port->mmio	= dd->mmio + PORT_OFFSET;
2752  | 	dd->port->dd	= dd;
2753  |
2754  |  /* DMA allocations */
2795  |  dev_err(&dd->pdev->dev,
2796  |  "Card did not reset within timeout\n");
2797  | 			rv = -EIO;
2798  |  goto out2;
2799  | 		}
2800  | 	} else {
2801  |  /* Clear any pending interrupts on the HBA */
2802  |  writel(readl(dd->mmio + HOST_IRQ_STAT),
2803  | 			dd->mmio + HOST_IRQ_STAT);
2804  | 	}
2805  |
2806  | 	mtip_init_port(dd->port);
2807  | 	mtip_start_port(dd->port);
2808  |
2809  |  /* Setup the ISR and enable interrupts. */
2810  | 	rv = request_irq(dd->pdev->irq, mtip_irq_handler, IRQF_SHARED,
2811  | 			 dev_driver_string(&dd->pdev->dev), dd);
2812  |  if (rv) {
2813  |  dev_err(&dd->pdev->dev,
2814  |  "Unable to allocate IRQ %d\n", dd->pdev->irq);
2815  |  goto out2;
2816  | 	}
2817  | 	irq_set_affinity_hint(dd->pdev->irq, get_cpu_mask(dd->isr_binding));
2818  |
2819  |  /* Enable interrupts on the HBA. */
2820  |  writel(readl(dd->mmio + HOST_CTL) | HOST_IRQ_EN,
2821  | 					dd->mmio + HOST_CTL);
2822  |
2823  |  init_waitqueue_head(&dd->port->svc_wait);
2824  |
2825  |  if (test_bit(MTIP_DDF_REMOVE_PENDING_BIT, &dd->dd_flag)) {
2826  | 		rv = -EFAULT;
2827  |  goto out3;
2828  | 	}
2829  |
2830  |  return rv;
2831  |
2832  | out3:
2833  |  /* Disable interrupts on the HBA. */
2834  |  writel(readl(dd->mmio + HOST_CTL) & ~HOST_IRQ_EN,
2835  | 			dd->mmio + HOST_CTL);
2836  |
2837  |  /* Release the IRQ. */
2838  | 	irq_set_affinity_hint(dd->pdev->irq, NULL);
2839  | 	free_irq(dd->pdev->irq, dd);
2840  |
2841  | out2:
2842  | 	mtip_deinit_port(dd->port);
2843  | 	mtip_dma_free(dd);
2844  |
2845  | out1:
2846  |  /* Free the memory allocated for the for structure. */
2847  |  kfree(dd->port);
    3←Freeing unowned field in shared error label; possible double free
2848  |
2849  |  return rv;
2850  | }
2851  |
2852  | static int mtip_standby_drive(struct driver_data *dd)
2853  | {
2854  |  int rv = 0;
2855  |
2856  |  if (dd->sr || !dd->port)
2857  |  return -ENODEV;
2858  |  /*
2859  |  * Send standby immediate (E0h) to the drive so that it
2860  |  * saves its state.
2861  |  */
2862  |  if (!test_bit(MTIP_PF_REBUILD_BIT, &dd->port->flags) &&
2863  | 	    !test_bit(MTIP_DDF_REBUILD_FAILED_BIT, &dd->dd_flag) &&
2864  | 	    !test_bit(MTIP_DDF_SEC_LOCK_BIT, &dd->dd_flag)) {
2865  | 		rv = mtip_standby_immediate(dd->port);
2866  |  if (rv)
2867  |  dev_warn(&dd->pdev->dev,
2868  |  "STANDBY IMMEDIATE failed\n");
2869  | 	}
2870  |  return rv;
2871  | }
2872  |
2873  | /*
2874  |  * Called to deinitialize an interface.
2875  |  *
2876  |  * @dd Pointer to the driver data structure.
2877  |  *

Analysis:
- Decision: NotABug
- Reason: The reported pattern does not match the target bug pattern and is not a real bug here. In mtip_hw_init(), the only unconditional free at the shared error label is kfree(dd->port). The function allocates dd->port locally (kzalloc_node) after the product-type check; the early goto out1 path occurs before any allocation, so dd->port remains NULL as driver_data is typically kzalloc’ed at probe. kfree(NULL) is safe (no-op). On later error paths (out3/out2), the code first deinitializes subresources (mtip_deinit_port(dd->port), mtip_dma_free(dd)) and then frees the port structure at out1—this respects ownership; those callees do not free dd->port itself. There is no callee that may conditionally free dd->port, so no double free risk from the shared label. Hence, this does not exhibit the target “freeing callee-managed memory via shared error label” bug.

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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: symbols returned by allocators.
REGISTER_SET_WITH_PROGRAMSTATE(AllocSymSet, SymbolRef)
// Program state: regions that this function explicitly owns (assigned an allocator return).
REGISTER_SET_WITH_PROGRAMSTATE(OwnedRegionSet, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
                             check::BeginFunction,
                             check::EndFunction,
                             check::PostCall,
                             check::PreCall,
                             check::Bind> {
  mutable std::unique_ptr<BugType> BT;

  // Per-function: how many gotos target each label.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, unsigned>> FuncLabelIncoming;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double free in shared error label", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to collect labels and gotos from a function body.
  struct LabelGotoCollector : public RecursiveASTVisitor<LabelGotoCollector> {
    llvm::DenseMap<const LabelDecl *, const LabelStmt *> LabelMap;
    llvm::SmallVector<const GotoStmt *, 16> Gotos;

    bool VisitLabelStmt(const LabelStmt *LS) {
      if (const LabelDecl *LD = LS->getDecl())
        LabelMap[LD] = LS;
      return true;
    }

    bool VisitGotoStmt(const GotoStmt *GS) {
      Gotos.push_back(GS);
      return true;
    }
  };

  const FunctionDecl *getCurrentFunction(const CheckerContext &C) const {
    const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return D;
  }

  void buildLabelIncomingMapForFunction(const FunctionDecl *FD) const;

  bool isAllocatorCall(const CallEvent &Call, CheckerContext &C) const;
  bool isFreeLikeCall(const CallEvent &Call, CheckerContext &C) const;

  void reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::buildLabelIncomingMapForFunction(const FunctionDecl *FD) const {
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  LabelGotoCollector Collector;
  Collector.TraverseStmt(const_cast<Stmt *>(Body));

  llvm::DenseMap<const LabelStmt*, unsigned> IncomingCount;
  for (const GotoStmt *GS : Collector.Gotos) {
    const LabelDecl *LD = GS->getLabel();
    if (!LD)
      continue;
    auto It = Collector.LabelMap.find(LD);
    if (It == Collector.LabelMap.end())
      continue;
    const LabelStmt *LS = It->second;
    IncomingCount[LS] = IncomingCount.lookup(LS) + 1;
  }

  FuncLabelIncoming[FD] = std::move(IncomingCount);
}

bool SAGenTestChecker::isAllocatorCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  // Typical Linux allocators.
  static const char *Names[] = {
      "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
      "devm_kmalloc", "devm_kzalloc", "devm_kcalloc"
  };
  for (const char *N : Names) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isFreeLikeCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  static const char *Names[] = {"kfree", "kvfree", "vfree"};
  for (const char *N : Names) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Rebuild (or build) label incoming counts for this function.
  buildLabelIncomingMapForFunction(FD);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Clean per-function metadata.
  FuncLabelIncoming.erase(FD);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isAllocatorCall(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef RetSym = Ret.getAsSymbol();
  if (!RetSym)
    return;

  if (!State->contains<AllocSymSet>(RetSym)) {
    State = State->add<AllocSymSet>(RetSym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstReg = Loc.getAsRegion();
  if (!DstReg)
    return;
  DstReg = DstReg->getBaseRegion();
  if (!DstReg)
    return;

  SymbolRef RHSym = Val.getAsSymbol();
  if (!RHSym)
    return;

  if (State->contains<AllocSymSet>(RHSym)) {
    if (!State->contains<OwnedRegionSet>(DstReg)) {
      State = State->add<OwnedRegionSet>(DstReg);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing unowned field in shared error label; possible double free", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isFreeLikeCall(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return;

  // Reduce FPs: only warn when freeing a struct/union field like mt->fc.
  const Expr *Stripped = ArgE->IgnoreParenImpCasts();
  if (!isa<MemberExpr>(Stripped))
    return;

  // Get region of the freed expression (do not strip casts before calling).
  const MemRegion *FreedReg = getMemRegionFromExpr(ArgE, C);
  if (!FreedReg)
    return;
  FreedReg = FreedReg->getBaseRegion();
  if (!FreedReg)
    return;

  ProgramStateRef State = C.getState();
  // If this function has taken ownership of this region (or its base), do not warn.
  if (State->contains<OwnedRegionSet>(FreedReg))
    return;

  // Determine if the call is under a label with multiple incoming gotos.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const LabelStmt *EnclosingLabel = findSpecificTypeInParents<LabelStmt>(Origin, C);
  if (!EnclosingLabel)
    return;

  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;

  auto Fit = FuncLabelIncoming.find(FD);
  if (Fit == FuncLabelIncoming.end())
    return;

  const auto &IncomingMap = Fit->second;
  auto Lit = IncomingMap.find(EnclosingLabel);
  unsigned Count = (Lit == IncomingMap.end()) ? 0u : Lit->second;

  // Only warn for shared labels (2 or more incoming gotos).
  if (Count >= 2) {
    reportFreeUnownedInSharedLabel(Call, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing unowned fields in shared error labels that may cause double free",
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
