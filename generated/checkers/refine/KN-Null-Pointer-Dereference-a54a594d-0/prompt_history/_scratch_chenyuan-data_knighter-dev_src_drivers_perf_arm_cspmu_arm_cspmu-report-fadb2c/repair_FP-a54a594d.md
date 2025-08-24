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

Performing an invalid-parameter check that only logs but does not abort, then immediately dereferencing/using the parameter (and its fields) anyway—combined with doing this validation outside the lock that protects the related shared state. In code form:

if (!obj || obj->idx_invalid || obj->idx >= max)
    log("invalid")
/* no return */
lock()
idx = obj->idx            // potential NULL deref or stale/invalid index
use obj and array[idx]    // potential OOB/race

This “log-and-continue after failed check” plus “validation outside the protecting lock” pattern can lead to NULL pointer dereferences and race-induced invalid accesses.

The patch that needs to be detected:

## Patch Description

xhci: fix possible null pointer dereference at secondary interrupter removal

Don't try to remove a secondary interrupter that is known to be invalid.
Also check if the interrupter is valid inside the spinlock that protects
the array of interrupters.

Found by smatch static checker

Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Closes: https://lore.kernel.org/linux-usb/ffaa0a1b-5984-4a1f-bfd3-9184630a97b9@moroto.mountain/
Fixes: c99b38c41234 ("xhci: add support to allocate several interrupters")
Signed-off-by: Mathias Nyman <mathias.nyman@linux.intel.com>
Link: https://lore.kernel.org/r/20240125152737.2983959-2-mathias.nyman@linux.intel.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

## Buggy Code

```c
// Function: xhci_remove_secondary_interrupter in drivers/usb/host/xhci-mem.c
void xhci_remove_secondary_interrupter(struct usb_hcd *hcd, struct xhci_interrupter *ir)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	unsigned int intr_num;

	/* interrupter 0 is primary interrupter, don't touch it */
	if (!ir || !ir->intr_num || ir->intr_num >= xhci->max_interrupters)
		xhci_dbg(xhci, "Invalid secondary interrupter, can't remove\n");

	/* fixme, should we check xhci->interrupter[intr_num] == ir */
	/* fixme locking */

	spin_lock_irq(&xhci->lock);

	intr_num = ir->intr_num;

	xhci_remove_interrupter(xhci, ir);
	xhci->interrupters[intr_num] = NULL;

	spin_unlock_irq(&xhci->lock);

	xhci_free_interrupter(xhci, ir);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/usb/host/xhci-mem.c b/drivers/usb/host/xhci-mem.c
index 4460fa7e9fab..d00d4d937236 100644
--- a/drivers/usb/host/xhci-mem.c
+++ b/drivers/usb/host/xhci-mem.c
@@ -1861,14 +1861,14 @@ void xhci_remove_secondary_interrupter(struct usb_hcd *hcd, struct xhci_interrup
 	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
 	unsigned int intr_num;

+	spin_lock_irq(&xhci->lock);
+
 	/* interrupter 0 is primary interrupter, don't touch it */
-	if (!ir || !ir->intr_num || ir->intr_num >= xhci->max_interrupters)
+	if (!ir || !ir->intr_num || ir->intr_num >= xhci->max_interrupters) {
 		xhci_dbg(xhci, "Invalid secondary interrupter, can't remove\n");
-
-	/* fixme, should we check xhci->interrupter[intr_num] == ir */
-	/* fixme locking */
-
-	spin_lock_irq(&xhci->lock);
+		spin_unlock_irq(&xhci->lock);
+		return;
+	}

 	intr_num = ir->intr_num;

```


# False Positive Report

### Report Summary

File:| drivers/perf/arm_cspmu/arm_cspmu.c
---|---
Warning:| line 445, column 7
Invalid-checked pointer is logged but not aborted; later dereferenced under
lock

### Annotated Source Code


66    | #define PMCFGR_FZO BIT(21)
67    | #define PMCFGR_MSI BIT(20)
68    | #define PMCFGR_UEN BIT(19)
69    | #define PMCFGR_NA BIT(17)
70    | #define PMCFGR_EX BIT(16)
71    | #define PMCFGR_CCD BIT(15)
72    | #define PMCFGR_CC BIT(14)
73    | #define PMCFGR_SIZE GENMASK(13, 8)
74    | #define PMCFGR_N GENMASK(7, 0)
75    |
76    | /* PMCR register field */
77    | #define PMCR_TRO BIT(11)
78    | #define PMCR_HDBG BIT(10)
79    | #define PMCR_FZO BIT(9)
80    | #define PMCR_NA BIT(8)
81    | #define PMCR_DP BIT(5)
82    | #define PMCR_X BIT(4)
83    | #define PMCR_D BIT(3)
84    | #define PMCR_C BIT(2)
85    | #define PMCR_P BIT(1)
86    | #define PMCR_E BIT(0)
87    |
88    | /* Each SET/CLR register supports up to 32 counters. */
89    | #define ARM_CSPMU_SET_CLR_COUNTER_SHIFT		5
90    | #define ARM_CSPMU_SET_CLR_COUNTER_NUM		\
91    |  (1 << ARM_CSPMU_SET_CLR_COUNTER_SHIFT)
92    |
93    | /* Convert counter idx into SET/CLR register number. */
94    | #define COUNTER_TO_SET_CLR_ID(idx)			\
95    |  (idx >> ARM_CSPMU_SET_CLR_COUNTER_SHIFT)
96    |
97    | /* Convert counter idx into SET/CLR register bit. */
98    | #define COUNTER_TO_SET_CLR_BIT(idx)			\
99    |  (idx & (ARM_CSPMU_SET_CLR_COUNTER_NUM - 1))
100   |
101   | #define ARM_CSPMU_ACTIVE_CPU_MASK		0x0
102   | #define ARM_CSPMU_ASSOCIATED_CPU_MASK		0x1
103   |
104   | /*
105   |  * Maximum poll count for reading counter value using high-low-high sequence.
106   |  */
107   | #define HILOHI_MAX_POLL	1000
108   |
109   | static unsigned long arm_cspmu_cpuhp_state;
110   |
111   | static DEFINE_MUTEX(arm_cspmu_lock);
112   |
113   | static void arm_cspmu_set_ev_filter(struct arm_cspmu *cspmu,
114   |  struct hw_perf_event *hwc, u32 filter);
115   |
116   | static struct acpi_apmt_node *arm_cspmu_apmt_node(struct device *dev)
117   | {
118   |  struct acpi_apmt_node **ptr = dev_get_platdata(dev);
119   |
120   |  return ptr ? *ptr : NULL;
121   | }
122   |
123   | /*
124   |  * In CoreSight PMU architecture, all of the MMIO registers are 32-bit except
125   |  * counter register. The counter register can be implemented as 32-bit or 64-bit
126   |  * register depending on the value of PMCFGR.SIZE field. For 64-bit access,
127   |  * single-copy 64-bit atomic support is implementation defined. APMT node flag
128   |  * is used to identify if the PMU supports 64-bit single copy atomic. If 64-bit
129   |  * single copy atomic is not supported, the driver treats the register as a pair
130   |  * of 32-bit register.
131   |  */
132   |
133   | /*
134   |  * Read 64-bit register as a pair of 32-bit registers using hi-lo-hi sequence.
135   |  */
136   | static u64 read_reg64_hilohi(const void __iomem *addr, u32 max_poll_count)
137   | {
138   | 	u32 val_lo, val_hi;
139   | 	u64 val;
140   |
141   |  /* Use high-low-high sequence to avoid tearing */
142   |  do {
143   |  if (max_poll_count-- == 0) {
144   |  pr_err("ARM CSPMU: timeout hi-low-high sequence\n");
145   |  return 0;
146   | 		}
147   |
148   | 		val_hi = readl(addr + 4);
149   | 		val_lo = readl(addr);
150   | 	} while (val_hi != readl(addr + 4));
363   |  return 0;
364   | 	}
365   |  return cpumap_print_to_pagebuf(true, buf, cpumask);
366   | }
367   |
368   | static struct attribute *arm_cspmu_cpumask_attrs[] = {
369   |  ARM_CSPMU_CPUMASK_ATTR(cpumask, ARM_CSPMU_ACTIVE_CPU_MASK),
370   |  ARM_CSPMU_CPUMASK_ATTR(associated_cpus, ARM_CSPMU_ASSOCIATED_CPU_MASK),
371   |  NULL,
372   | };
373   |
374   | static struct attribute_group arm_cspmu_cpumask_attr_group = {
375   | 	.attrs = arm_cspmu_cpumask_attrs,
376   | };
377   |
378   | static struct arm_cspmu_impl_match impl_match[] = {
379   | 	{
380   | 		.module_name	= "nvidia_cspmu",
381   | 		.pmiidr_val	= ARM_CSPMU_IMPL_ID_NVIDIA,
382   | 		.pmiidr_mask	= ARM_CSPMU_PMIIDR_IMPLEMENTER,
383   | 		.module		= NULL,
384   | 		.impl_init_ops	= NULL,
385   | 	},
386   | 	{
387   | 		.module_name	= "ampere_cspmu",
388   | 		.pmiidr_val	= ARM_CSPMU_IMPL_ID_AMPERE,
389   | 		.pmiidr_mask	= ARM_CSPMU_PMIIDR_IMPLEMENTER,
390   | 		.module		= NULL,
391   | 		.impl_init_ops	= NULL,
392   | 	},
393   |
394   | 	{0}
395   | };
396   |
397   | static struct arm_cspmu_impl_match *arm_cspmu_impl_match_get(u32 pmiidr)
398   | {
399   |  struct arm_cspmu_impl_match *match = impl_match;
400   |
401   |  for (; match->pmiidr_val; match++) {
402   | 		u32 mask = match->pmiidr_mask;
403   |
404   |  if ((match->pmiidr_val & mask) == (pmiidr & mask))
405   |  return match;
406   | 	}
407   |
408   |  return NULL;
409   | }
410   |
411   | #define DEFAULT_IMPL_OP(name)	.name = arm_cspmu_##name
412   |
413   | static int arm_cspmu_init_impl_ops(struct arm_cspmu *cspmu)
414   | {
415   |  int ret = 0;
416   |  struct acpi_apmt_node *apmt_node = arm_cspmu_apmt_node(cspmu->dev);
417   |  struct arm_cspmu_impl_match *match;
418   |
419   |  /* Start with a default PMU implementation */
420   | 	cspmu->impl.module = THIS_MODULE;
421   | 	cspmu->impl.pmiidr = readl(cspmu->base0 + PMIIDR);
422   | 	cspmu->impl.ops = (struct arm_cspmu_impl_ops) {
423   |  DEFAULT_IMPL_OP(get_event_attrs),
424   |  DEFAULT_IMPL_OP(get_format_attrs),
425   |  DEFAULT_IMPL_OP(get_identifier),
426   |  DEFAULT_IMPL_OP(get_name),
427   |  DEFAULT_IMPL_OP(is_cycle_counter_event),
428   |  DEFAULT_IMPL_OP(event_type),
429   |  DEFAULT_IMPL_OP(event_filter),
430   |  DEFAULT_IMPL_OP(set_ev_filter),
431   |  DEFAULT_IMPL_OP(event_attr_is_visible),
432   | 	};
433   |
434   |  /* Firmware may override implementer/product ID from PMIIDR */
435   |  if (apmt_node6.1'apmt_node' is null && apmt_node->impl_id)
436   | 		cspmu->impl.pmiidr = apmt_node->impl_id;
437   |
438   |  /* Find implementer specific attribute ops. */
439   |  match = arm_cspmu_impl_match_get(cspmu->impl.pmiidr);
440   |
441   |  /* Load implementer module and initialize the callbacks. */
442   |  if (match) {
    7←Assuming 'match' is non-null→
    8←Taking true branch→
443   |  mutex_lock(&arm_cspmu_lock);
444   |
445   |  if (match->impl_init_ops) {
    9←Invalid-checked pointer is logged but not aborted; later dereferenced under lock
446   |  /* Prevent unload until PMU registration is done. */
447   |  if (try_module_get(match->module)) {
448   | 				cspmu->impl.module = match->module;
449   | 				cspmu->impl.match = match;
450   | 				ret = match->impl_init_ops(cspmu);
451   |  if (ret)
452   | 					module_put(match->module);
453   | 			} else {
454   |  WARN(1, "arm_cspmu failed to get module: %s\n",
455   |  match->module_name);
456   | 				ret = -EINVAL;
457   | 			}
458   | 		} else {
459   |  request_module_nowait(match->module_name);
460   | 			ret = -EPROBE_DEFER;
461   | 		}
462   |
463   | 		mutex_unlock(&arm_cspmu_lock);
464   | 	}
465   |
466   |  return ret;
467   | }
468   |
469   | static struct attribute_group *
470   | arm_cspmu_alloc_event_attr_group(struct arm_cspmu *cspmu)
471   | {
472   |  struct attribute_group *event_group;
473   |  struct device *dev = cspmu->dev;
474   |  const struct arm_cspmu_impl_ops *impl_ops = &cspmu->impl.ops;
475   |
886   | static int arm_cspmu_add(struct perf_event *event, int flags)
887   | {
888   |  struct arm_cspmu *cspmu = to_arm_cspmu(event->pmu);
889   |  struct arm_cspmu_hw_events *hw_events = &cspmu->hw_events;
890   |  struct hw_perf_event *hwc = &event->hw;
891   |  int idx;
892   |
893   |  if (WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(),
894   |  &cspmu->associated_cpus)))
895   |  return -ENOENT;
896   |
897   | 	idx = arm_cspmu_get_event_idx(hw_events, event);
898   |  if (idx < 0)
899   |  return idx;
900   |
901   | 	hw_events->events[idx] = event;
902   | 	hwc->idx = to_phys_idx(cspmu, idx);
903   | 	hwc->extra_reg.idx = idx;
904   | 	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;
905   |
906   |  if (flags & PERF_EF_START)
907   | 		arm_cspmu_start(event, PERF_EF_RELOAD);
908   |
909   |  /* Propagate changes to the userspace mapping. */
910   | 	perf_event_update_userpage(event);
911   |
912   |  return 0;
913   | }
914   |
915   | static void arm_cspmu_del(struct perf_event *event, int flags)
916   | {
917   |  struct arm_cspmu *cspmu = to_arm_cspmu(event->pmu);
918   |  struct arm_cspmu_hw_events *hw_events = &cspmu->hw_events;
919   |  struct hw_perf_event *hwc = &event->hw;
920   |  int idx = hwc->extra_reg.idx;
921   |
922   | 	arm_cspmu_stop(event, PERF_EF_UPDATE);
923   |
924   | 	hw_events->events[idx] = NULL;
925   |
926   | 	clear_bit(idx, hw_events->used_ctrs);
927   |
928   | 	perf_event_update_userpage(event);
929   | }
930   |
931   | static void arm_cspmu_read(struct perf_event *event)
932   | {
933   | 	arm_cspmu_event_update(event);
934   | }
935   |
936   | static struct arm_cspmu *arm_cspmu_alloc(struct platform_device *pdev)
937   | {
938   |  struct acpi_apmt_node *apmt_node;
939   |  struct arm_cspmu *cspmu;
940   |  struct device *dev = &pdev->dev;
941   |
942   | 	cspmu = devm_kzalloc(dev, sizeof(*cspmu), GFP_KERNEL);
943   |  if (!cspmu)
944   |  return NULL;
945   |
946   | 	cspmu->dev = dev;
947   | 	platform_set_drvdata(pdev, cspmu);
948   |
949   | 	apmt_node = arm_cspmu_apmt_node(dev);
950   |  if (apmt_node) {
951   | 		cspmu->has_atomic_dword = apmt_node->flags & ACPI_APMT_FLAGS_ATOMIC;
952   | 	} else {
953   | 		u32 width = 0;
954   |
955   | 		device_property_read_u32(dev, "reg-io-width", &width);
956   | 		cspmu->has_atomic_dword = (width == 8);
957   | 	}
958   |
959   |  return cspmu;
960   | }
961   |
962   | static int arm_cspmu_init_mmio(struct arm_cspmu *cspmu)
963   | {
964   |  struct device *dev;
965   |  struct platform_device *pdev;
966   |
967   | 	dev = cspmu->dev;
968   | 	pdev = to_platform_device(dev);
969   |
970   |  /* Base address for page 0. */
971   | 	cspmu->base0 = devm_platform_ioremap_resource(pdev, 0);
972   |  if (IS_ERR(cspmu->base0)) {
973   |  dev_err(dev, "ioremap failed for page-0 resource\n");
974   |  return PTR_ERR(cspmu->base0);
975   | 	}
976   |
977   |  /* Base address for page 1 if supported. Otherwise point to page 0. */
978   | 	cspmu->base1 = cspmu->base0;
979   |  if (platform_get_resource(pdev, IORESOURCE_MEM, 1)) {
980   | 		cspmu->base1 = devm_platform_ioremap_resource(pdev, 1);
981   |  if (IS_ERR(cspmu->base1)) {
982   |  dev_err(dev, "ioremap failed for page-1 resource\n");
983   |  return PTR_ERR(cspmu->base1);
984   | 		}
985   | 	}
986   |
987   | 	cspmu->pmcfgr = readl(cspmu->base0 + PMCFGR);
988   |
989   | 	cspmu->num_logical_ctrs = FIELD_GET(PMCFGR_N, cspmu->pmcfgr) + 1;
990   |
991   | 	cspmu->cycle_counter_logical_idx = ARM_CSPMU_MAX_HW_CNTRS;
992   |
993   |  if (supports_cycle_counter(cspmu)) {
994   |  /*
995   |  * The last logical counter is mapped to cycle counter if
996   |  * there is a gap between regular and cycle counter. Otherwise,
997   |  * logical and physical have 1-to-1 mapping.
998   |  */
999   | 		cspmu->cycle_counter_logical_idx =
1000  | 			(cspmu->num_logical_ctrs <= ARM_CSPMU_CYCLE_CNTR_IDX) ?
1001  | 				cspmu->num_logical_ctrs - 1 :
1002  |  ARM_CSPMU_CYCLE_CNTR_IDX;
1003  | 	}
1004  |
1021  | {
1022  |  int i;
1023  | 	u32 pmovclr_offset = PMOVSCLR;
1024  | 	u32 has_overflowed = 0;
1025  |
1026  |  for (i = 0; i < cspmu->num_set_clr_reg; ++i) {
1027  | 		pmovs[i] = readl(cspmu->base1 + pmovclr_offset);
1028  | 		has_overflowed |= pmovs[i];
1029  |  writel(pmovs[i], cspmu->base1 + pmovclr_offset);
1030  | 		pmovclr_offset += sizeof(u32);
1031  | 	}
1032  |
1033  |  return has_overflowed != 0;
1034  | }
1035  |
1036  | static irqreturn_t arm_cspmu_handle_irq(int irq_num, void *dev)
1037  | {
1038  |  int idx, has_overflowed;
1039  |  struct perf_event *event;
1040  |  struct arm_cspmu *cspmu = dev;
1041  |  DECLARE_BITMAP(pmovs, ARM_CSPMU_MAX_HW_CNTRS);
1042  | 	bool handled = false;
1043  |
1044  | 	arm_cspmu_stop_counters(cspmu);
1045  |
1046  | 	has_overflowed = arm_cspmu_get_reset_overflow(cspmu, (u32 *)pmovs);
1047  |  if (!has_overflowed)
1048  |  goto done;
1049  |
1050  |  for_each_set_bit(idx, cspmu->hw_events.used_ctrs,
1051  |  cspmu->num_logical_ctrs) {
1052  | 		event = cspmu->hw_events.events[idx];
1053  |
1054  |  if (!event)
1055  |  continue;
1056  |
1057  |  if (!test_bit(event->hw.idx, pmovs))
1058  |  continue;
1059  |
1060  | 		arm_cspmu_event_update(event);
1061  | 		arm_cspmu_set_event_period(event);
1062  |
1063  | 		handled = true;
1064  | 	}
1065  |
1066  | done:
1067  | 	arm_cspmu_start_counters(cspmu);
1068  |  return IRQ_RETVAL(handled);
1069  | }
1070  |
1071  | static int arm_cspmu_request_irq(struct arm_cspmu *cspmu)
1072  | {
1073  |  int irq, ret;
1074  |  struct device *dev;
1075  |  struct platform_device *pdev;
1076  |
1077  | 	dev = cspmu->dev;
1078  | 	pdev = to_platform_device(dev);
1079  |
1080  |  /* Skip IRQ request if the PMU does not support overflow interrupt. */
1081  | 	irq = platform_get_irq_optional(pdev, 0);
1082  |  if (irq < 0)
1083  |  return irq == -ENXIO ? 0 : irq;
1084  |
1085  | 	ret = devm_request_irq(dev, irq, arm_cspmu_handle_irq,
1086  |  IRQF_NOBALANCING | IRQF_NO_THREAD, dev_name(dev),
1087  | 			       cspmu);
1088  |  if (ret) {
1089  |  dev_err(dev, "Could not request IRQ %d\n", irq);
1090  |  return ret;
1091  | 	}
1092  |
1093  | 	cspmu->irq = irq;
1094  |
1095  |  return 0;
1096  | }
1097  |
1098  | #if defined(CONFIG_ACPI) && defined(CONFIG_ARM64)
1099  | #include <acpi/processor.h>
1100  |
1101  | static inline int arm_cspmu_find_cpu_container(int cpu, u32 container_uid)
1102  | {
1103  |  struct device *cpu_dev;
1104  |  struct acpi_device *acpi_dev;
1105  |
1106  | 	cpu_dev = get_cpu_device(cpu);
1107  |  if (!cpu_dev)
1108  |  return -ENODEV;
1109  |
1110  | 	acpi_dev = ACPI_COMPANION(cpu_dev);
1111  |  while (acpi_dev) {
1112  |  if (acpi_dev_hid_uid_match(acpi_dev, ACPI_PROCESSOR_CONTAINER_HID, container_uid))
1113  |  return 0;
1114  |
1115  | 		acpi_dev = acpi_dev_parent(acpi_dev);
1116  | 	}
1117  |
1118  |  return -ENODEV;
1119  | }
1120  |
1121  | static int arm_cspmu_acpi_get_cpus(struct arm_cspmu *cspmu)
1122  | {
1123  |  struct acpi_apmt_node *apmt_node;
1124  |  int affinity_flag;
1125  |  int cpu;
1126  |
1127  | 	apmt_node = arm_cspmu_apmt_node(cspmu->dev);
1128  | 	affinity_flag = apmt_node->flags & ACPI_APMT_FLAGS_AFFINITY;
1129  |
1130  |  if (affinity_flag == ACPI_APMT_FLAGS_AFFINITY_PROC) {
1131  |  for_each_possible_cpu(cpu) {
1132  |  if (apmt_node->proc_affinity ==
1133  | 			    get_acpi_id_for_cpu(cpu)) {
1134  | 				cpumask_set_cpu(cpu, &cspmu->associated_cpus);
1135  |  break;
1136  | 			}
1137  | 		}
1138  | 	} else {
1139  |  for_each_possible_cpu(cpu) {
1140  |  if (arm_cspmu_find_cpu_container(
1141  | 				    cpu, apmt_node->proc_affinity))
1142  |  continue;
1143  |
1144  | 			cpumask_set_cpu(cpu, &cspmu->associated_cpus);
1145  | 		}
1146  | 	}
1147  |
1148  |  return 0;
1149  | }
1150  | #else
1151  | static int arm_cspmu_acpi_get_cpus(struct arm_cspmu *cspmu)
1152  | {
1153  |  return -ENODEV;
1154  | }
1155  | #endif
1156  |
1157  | static int arm_cspmu_of_get_cpus(struct arm_cspmu *cspmu)
1158  | {
1159  |  struct of_phandle_iterator it;
1160  |  int ret, cpu;
1161  |
1162  |  of_for_each_phandle(&it, ret, dev_of_node(cspmu->dev), "cpus", NULL, 0) {
1163  | 		cpu = of_cpu_node_to_id(it.node);
1164  |  if (cpu < 0)
1165  |  continue;
1166  | 		cpumask_set_cpu(cpu, &cspmu->associated_cpus);
1167  | 	}
1168  |  return ret == -ENOENT ? 0 : ret;
1169  | }
1170  |
1171  | static int arm_cspmu_get_cpus(struct arm_cspmu *cspmu)
1172  | {
1173  |  int ret = 0;
1174  |
1175  |  if (arm_cspmu_apmt_node(cspmu->dev))
1176  | 		ret = arm_cspmu_acpi_get_cpus(cspmu);
1177  |  else if (device_property_present(cspmu->dev, "cpus"))
1178  | 		ret = arm_cspmu_of_get_cpus(cspmu);
1179  |  else
1180  | 		cpumask_copy(&cspmu->associated_cpus, cpu_possible_mask);
1181  |
1182  |  if (!ret && cpumask_empty(&cspmu->associated_cpus)) {
1183  |  dev_dbg(cspmu->dev, "No cpu associated with the PMU\n");
1184  | 		ret = -ENODEV;
1185  | 	}
1186  |  return ret;
1187  | }
1188  |
1189  | static int arm_cspmu_register_pmu(struct arm_cspmu *cspmu)
1190  | {
1191  |  int ret, capabilities;
1192  |
1193  | 	ret = arm_cspmu_alloc_attr_groups(cspmu);
1194  |  if (ret)
1195  |  return ret;
1196  |
1197  | 	ret = cpuhp_state_add_instance(arm_cspmu_cpuhp_state,
1198  | 				       &cspmu->cpuhp_node);
1199  |  if (ret)
1200  |  return ret;
1201  |
1202  | 	capabilities = PERF_PMU_CAP_NO_EXCLUDE;
1203  |  if (cspmu->irq == 0)
1204  | 		capabilities |= PERF_PMU_CAP_NO_INTERRUPT;
1205  |
1206  | 	cspmu->pmu = (struct pmu){
1207  | 		.task_ctx_nr	= perf_invalid_context,
1208  | 		.module		= cspmu->impl.module,
1209  | 		.pmu_enable	= arm_cspmu_enable,
1210  | 		.pmu_disable	= arm_cspmu_disable,
1211  | 		.event_init	= arm_cspmu_event_init,
1212  | 		.add		= arm_cspmu_add,
1213  | 		.del		= arm_cspmu_del,
1214  | 		.start		= arm_cspmu_start,
1215  | 		.stop		= arm_cspmu_stop,
1216  | 		.read		= arm_cspmu_read,
1217  | 		.attr_groups	= cspmu->attr_groups,
1218  | 		.capabilities	= capabilities,
1219  | 	};
1220  |
1221  |  /* Hardware counter init */
1222  | 	arm_cspmu_reset_counters(cspmu);
1223  |
1224  | 	ret = perf_pmu_register(&cspmu->pmu, cspmu->name, -1);
1225  |  if (ret) {
1226  | 		cpuhp_state_remove_instance(arm_cspmu_cpuhp_state,
1227  | 					    &cspmu->cpuhp_node);
1228  | 	}
1229  |
1230  |  return ret;
1231  | }
1232  |
1233  | static int arm_cspmu_device_probe(struct platform_device *pdev)
1234  | {
1235  |  int ret;
1236  |  struct arm_cspmu *cspmu;
1237  |
1238  | 	cspmu = arm_cspmu_alloc(pdev);
1239  |  if (!cspmu0.1'cspmu' is non-null)
    1Taking false branch→
1240  |  return -ENOMEM;
1241  |
1242  |  ret = arm_cspmu_init_mmio(cspmu);
1243  |  if (ret)
    2←Assuming 'ret' is 0→
    3←Taking false branch→
1244  |  return ret;
1245  |
1246  |  ret = arm_cspmu_request_irq(cspmu);
1247  |  if (ret3.1'ret' is 0)
    4←Taking false branch→
1248  |  return ret;
1249  |
1250  |  ret = arm_cspmu_get_cpus(cspmu);
1251  |  if (ret4.1'ret' is 0)
    5←Taking false branch→
1252  |  return ret;
1253  |
1254  |  ret = arm_cspmu_init_impl_ops(cspmu);
    6←Calling 'arm_cspmu_init_impl_ops'→
1255  |  if (ret)
1256  |  return ret;
1257  |
1258  | 	ret = arm_cspmu_register_pmu(cspmu);
1259  |
1260  |  /* Matches arm_cspmu_init_impl_ops() above. */
1261  |  if (cspmu->impl.module != THIS_MODULE)
1262  | 		module_put(cspmu->impl.module);
1263  |
1264  |  return ret;
1265  | }
1266  |
1267  | static void arm_cspmu_device_remove(struct platform_device *pdev)
1268  | {
1269  |  struct arm_cspmu *cspmu = platform_get_drvdata(pdev);
1270  |
1271  | 	perf_pmu_unregister(&cspmu->pmu);
1272  | 	cpuhp_state_remove_instance(arm_cspmu_cpuhp_state, &cspmu->cpuhp_node);
1273  | }
1274  |
1275  | static const struct platform_device_id arm_cspmu_id[] = {
1276  | 	{DRVNAME, 0},
1277  | 	{ },
1278  | };
1279  | MODULE_DEVICE_TABLE(platform, arm_cspmu_id);
1280  |
1281  | static const struct of_device_id arm_cspmu_of_match[] = {
1282  | 	{ .compatible = "arm,coresight-pmu" },
1283  | 	{}
1284  | };

Analysis:
- Decision: NotABug
- Reason: The flagged code in arm_cspmu_init_impl_ops does not match the target “log-and-continue after failed check done outside the protecting lock” pattern and does not constitute a real bug.

  Control/data flow:
  - match is obtained via arm_cspmu_impl_match_get(). It is either NULL or a pointer to a static entry in the impl_match[] array.
  - The code explicitly checks if (match) before taking the mutex and dereferencing any fields of match. All subsequent dereferences occur inside the if (match) block.
  - Inside the lock:
    - If match->impl_init_ops is non-NULL, it calls it after successfully getting the module ref (try_module_get). If try_module_get fails, it emits a WARN and returns an error (-EINVAL). No dereference is performed after the failure/log.
    - If match->impl_init_ops is NULL, it requests the module asynchronously and returns -EPROBE_DEFER. This is a controlled abort, not “log-and-continue.”
  - There is no place where an invalid parameter is only logged and then used anyway. There is also no validation performed outside the lock that is relied upon later under the lock in a racy way. The check for match occurs outside, but the lock is only taken inside the if (match) block; no dereference happens when match is NULL.

  Null-pointer dereference feasibility:
  - match can be NULL. The code guards all uses with if (match).
  - match->impl_init_ops can be NULL. The code checks it and does not call it when NULL; instead it requests the module and returns -EPROBE_DEFER.
  - match points to a statically defined array entry; lifetime is global, so there is no lifetime/concurrency hazard.

  Therefore, the reported “invalid-checked pointer is logged but not aborted; later dereferenced under lock” does not occur here, and the code does not exhibit the target bug pattern.

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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// ---------------- Program States ----------------
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousNoLockSet, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousAfterLockSet, const MemRegion*)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LockDepth, int)

namespace {

/* The checker callbacks are to be decided. */
class SAGenTestChecker
  : public Checker<
      check::BranchCondition,
      check::PostCall,
      check::PreCall,
      check::Location,
      check::EndFunction> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Invalid check then deref under lock", "Concurrency")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:

      // Helpers
      bool isLockAcquire(const CallEvent &Call, CheckerContext &C) const;
      bool isLockRelease(const CallEvent &Call, CheckerContext &C) const;

      const MemRegion* extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const;
      bool thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const;

      const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      bool stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                const ProgramStateRef &State,
                                const MemRegion *&TrackedPtrOut) const;

      void reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const;

      // New helpers to reduce false positives
      bool containsLoggingCall(const Stmt *S, CheckerContext &C) const;
      static bool isLoggingName(StringRef Name);
};



// ---------------- Helper Implementations ----------------

static bool isNullLikeExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  // Check for null pointer constant per AST utilities
  if (E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull))
    return true;

  // Also try constant-evaluated integer 0
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C)) {
    if (Val == 0)
      return true;
  }
  return false;
}

const MemRegion* SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion* SAGenTestChecker::extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const {
  if (!Cond) return nullptr;
  const Expr *E = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LOr || Op == BO_LAnd) {
      // Recurse into both sides, prefer LHS first
      if (const MemRegion *R = extractNullCheckedPointer(BO->getLHS(), C))
        return R;
      return extractNullCheckedPointer(BO->getRHS(), C);
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSNull = isNullLikeExpr(LHS, C);
      bool RHSNull = isNullLikeExpr(RHS, C);

      // Look for (ptr == NULL) or (ptr != NULL)
      if (LHSNull && !RHSNull) {
        if (RHS->getType()->isAnyPointerType()) {
          if (isa<DeclRefExpr>(RHS))
            return getBaseRegionFromExpr(RHS, C);
        }
      } else if (RHSNull && !LHSNull) {
        if (LHS->getType()->isAnyPointerType()) {
          if (isa<DeclRefExpr>(LHS))
            return getBaseRegionFromExpr(LHS, C);
        }
      }
    }
  } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (Sub->getType()->isAnyPointerType() && isa<DeclRefExpr>(Sub)) {
        return getBaseRegionFromExpr(Sub, C);
      }
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    // In conditions like "if (ptr)" treat it as a null-check too.
    if (DRE->getType()->isAnyPointerType())
      return getBaseRegionFromExpr(DRE, C);
  }

  return nullptr;
}

bool SAGenTestChecker::thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const {
  if (!Then) return false;

  if (findSpecificTypeInChildren<ReturnStmt>(Then)) return true;
  if (findSpecificTypeInChildren<GotoStmt>(Then)) return true;
  if (findSpecificTypeInChildren<BreakStmt>(Then)) return true;
  if (findSpecificTypeInChildren<ContinueStmt>(Then)) return true;

  return false;
}

static bool stmtContainsCallWithName(const Stmt *S, StringRef Name, CheckerContext &C) {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    // Try callee identifier first
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD->getIdentifier()) {
        if (FD->getName().equals(Name))
          return true;
      }
    }
    // Fallback to source text name matching (macro-expanded cases)
    if (ExprHasName(CE->getCallee(), Name, C))
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (stmtContainsCallWithName(Child, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLoggingName(StringRef Name) {
  // Normalize to lowercase for case-insensitive matching.
  std::string LowerStr = Name.lower();
  StringRef L(LowerStr);
  return L.contains("dbg") ||
         L.contains("warn") ||
         L.contains("err") ||
         L.contains("printk") ||
         L.startswith("pr_") ||
         L.contains("log") ||
         L.startswith("dev_") ||
         L.equals("xhci_dbg") ||
         Name.contains("WARN");
}

bool SAGenTestChecker::containsLoggingCall(const Stmt *S, CheckerContext &C) const {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (const IdentifierInfo *ID = FD->getIdentifier()) {
        if (isLoggingName(ID->getName()))
          return true;
      }
    }
    // Fallback to textual sniffing on callee/source if no identifier
    const Expr *CalleeE = CE->getCallee();
    if (CalleeE) {
      const SourceManager &SM = C.getSourceManager();
      const LangOptions &LangOpts = C.getLangOpts();
      CharSourceRange Range = CharSourceRange::getTokenRange(CalleeE->getSourceRange());
      StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
      if (isLoggingName(Text))
        return true;
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsLoggingCall(Child, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLockAcquire(const CallEvent &Call, CheckerContext &C) const {
  // Prefer callee identifier when available
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();
    // Common Linux locking APIs
    static const char *LockNames[] = {
      "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "spin_lock_bh",
      "mutex_lock", "rt_mutex_lock", "raw_spin_lock",
      // XA/RCU-like helpers used as locks in some subsystems
      "xa_lock", "xa_lock_irq", "xa_lock_irqsave", "xa_lock_bh",
      "read_lock", "write_lock", "down_read", "down_write", "down"
    };
    for (const char *Name : LockNames)
      if (FnName.equals(Name))
        return true;
  }

  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  // Fallback textual match when identifier is not available or macro-expanded
  static const char *LockTextNames[] = {
    "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "spin_lock_bh",
    "mutex_lock", "rt_mutex_lock", "raw_spin_lock",
    "xa_lock", "xa_lock_irq", "xa_lock_irqsave", "xa_lock_bh",
    "read_lock", "write_lock", "down_read", "down_write", "down("
  };

  for (const char *Name : LockTextNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLockRelease(const CallEvent &Call, CheckerContext &C) const {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();
    static const char *UnlockNames[] = {
      "spin_unlock", "spin_unlock_irq", "spin_unlock_irqrestore", "spin_unlock_bh",
      "mutex_unlock", "rt_mutex_unlock", "raw_spin_unlock",
      "xa_unlock", "xa_unlock_irq", "xa_unlock_irqrestore", "xa_unlock_bh",
      "read_unlock", "write_unlock", "up_read", "up_write", "up"
    };
    for (const char *Name : UnlockNames)
      if (FnName.equals(Name))
        return true;
  }

  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  static const char *UnlockTextNames[] = {
    "spin_unlock", "spin_unlock_irq", "spin_unlock_irqrestore", "spin_unlock_bh",
    "mutex_unlock", "rt_mutex_unlock", "raw_spin_unlock",
    "xa_unlock", "xa_unlock_irq", "xa_unlock_irqrestore", "xa_unlock_bh",
    "read_unlock", "write_unlock", "up_read", "up_write", "up("
  };

  for (const char *Name : UnlockTextNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                            const ProgramStateRef &State,
                                            const MemRegion *&TrackedPtrOut) const {
  TrackedPtrOut = nullptr;
  if (!S) return false;

  // Look for "ptr->field"
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Base->IgnoreParenImpCasts())) {
        const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
        if (MR) {
          auto Set = State->get<SuspiciousAfterLockSet>();
          for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
            if (*I == MR) {
              TrackedPtrOut = MR;
              return true;
            }
          }
        }
      }
    }
  }

  // Look for "*ptr"
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
        if (MR) {
          auto Set = State->get<SuspiciousAfterLockSet>();
          for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
            if (*I == MR) {
              TrackedPtrOut = MR;
              return true;
            }
          }
        }
      }
    }
  }

  // Look for "ptr[idx]"
  if (const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
      if (MR) {
        auto Set = State->get<SuspiciousAfterLockSet>();
        for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
          if (*I == MR) {
            TrackedPtrOut = MR;
            return true;
          }
        }
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const {
  if (!R) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Invalid-checked pointer is logged but not aborted; later dereferenced under lock", N);
  if (S)
    Report->addRange(S->getSourceRange());
  Report->markInteresting(R);
  C.emitReport(std::move(Report));
}


// ---------------- Checker Callbacks ----------------

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // Find the containing IfStmt
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;

  const Stmt *Then = IS->getThen();
  // Identify the pointer that is being null-checked in the condition
  const MemRegion *R = extractNullCheckedPointer(Cond, C);
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();

  // If inside the lock and we see re-validation with early-exit, clear suspicion.
  if (Depth > 0) {
    if (thenHasEarlyExit(Then, C)) {
      State = State->remove<SuspiciousAfterLockSet>(R);
      C.addTransition(State);
    }
    return;
  }

  // We only care about the "log-and-continue" pattern outside the lock:
  // - Then branch must not have early exit
  // - Then branch must contain a logging call (dbg/warn/err/printk/...)
  if (thenHasEarlyExit(Then, C))
    return;

  if (!containsLoggingCall(Then, C))
    return; // Avoid FPs where the check is not "log-only".

  // Mark this pointer as suspicious: invalid-checked, no abort, and not under lock.
  State = State->add<SuspiciousNoLockSet>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isLockAcquire(Call, C)) {
    int Depth = State->get<LockDepth>();
    State = State->set<LockDepth>(Depth + 1);

    // Move all regions from SuspiciousNoLockSet to SuspiciousAfterLockSet
    auto NoLock = State->get<SuspiciousNoLockSet>();
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      const MemRegion *R = *I;
      State = State->add<SuspiciousAfterLockSet>(R);
    }
    // Clear SuspiciousNoLockSet after transferring
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      State = State->remove<SuspiciousNoLockSet>(*I);
    }

    C.addTransition(State);
    return;
  }

  if (isLockRelease(Call, C)) {
    int Depth = State->get<LockDepth>();
    if (Depth > 0)
      State = State->set<LockDepth>(Depth - 1);
    else
      State = State->set<LockDepth>(0);

    // When fully unlocked, clear AfterLockSet to avoid stale carry-over.
    int NewDepth = State->get<LockDepth>();
    if (NewDepth <= 0) {
      auto After = State->get<SuspiciousAfterLockSet>();
      for (auto I = After.begin(), E = After.end(); I != E; ++I) {
        State = State->remove<SuspiciousAfterLockSet>(*I);
      }
      State = State->set<LockDepth>(0);
    }

    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Only report deref if we're currently under a lock.
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

  // For calls that are known to dereference pointer arguments, check if any of those
  // arguments correspond to our suspicious pointer after the lock.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    // Is this pointer in the "after-lock" suspicious set?
    auto After = State->get<SuspiciousAfterLockSet>();
    bool Found = false;
    for (auto I = After.begin(), E = After.end(); I != E; ++I) {
      if (*I == MR) { Found = true; break; }
    }

    if (Found) {
      reportDerefBug(Call.getOriginExpr(), MR, C);
      // Remove to avoid duplicate reports.
      State = State->remove<SuspiciousAfterLockSet>(MR);
      C.addTransition(State);
      // do not return early; check other params as well
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

  // Heuristic: for members like ir->intr_num or deref *ir or arr like ir[idx],
  // extract the base DeclRefExpr and see if it matches our tracked pointer.
  const MemRegion *TrackedR = nullptr;
  if (stmtDerefsTrackedPtr(S, C, State, TrackedR) && TrackedR) {
    reportDerefBug(S, TrackedR, C);
    State = State->remove<SuspiciousAfterLockSet>(TrackedR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Best-effort cleanup of lock depth; sets will be discarded with state anyway.
  ProgramStateRef State = C.getState();
  State = State->set<LockDepth>(0);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects null-check that only logs without abort, then dereferences under lock",
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
