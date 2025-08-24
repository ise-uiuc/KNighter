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

File:| /scratch/chenyuan-data/linux-debug/drivers/pci/controller/pci-tegra.c
---|---
Warning:| line 1113, column 9
Shift done in 32-bit, widened after; cast left operand to 64-bit before <<

### Annotated Source Code


331   |
332   |  struct clk *pex_clk;
333   |  struct clk *afi_clk;
334   |  struct clk *pll_e;
335   |  struct clk *cml_clk;
336   |
337   |  struct reset_control *pex_rst;
338   |  struct reset_control *afi_rst;
339   |  struct reset_control *pcie_xrst;
340   |
341   | 	bool legacy_phy;
342   |  struct phy *phy;
343   |
344   |  struct tegra_msi msi;
345   |
346   |  struct list_head ports;
347   | 	u32 xbar_config;
348   |
349   |  struct regulator_bulk_data *supplies;
350   |  unsigned int num_supplies;
351   |
352   |  const struct tegra_pcie_soc *soc;
353   |  struct dentry *debugfs;
354   | };
355   |
356   | static inline struct tegra_pcie *msi_to_pcie(struct tegra_msi *msi)
357   | {
358   |  return container_of(msi, struct tegra_pcie, msi);
359   | }
360   |
361   | struct tegra_pcie_port {
362   |  struct tegra_pcie *pcie;
363   |  struct device_node *np;
364   |  struct list_head list;
365   |  struct resource regs;
366   |  void __iomem *base;
367   |  unsigned int index;
368   |  unsigned int lanes;
369   |
370   |  struct phy **phys;
371   |
372   |  struct gpio_desc *reset_gpio;
373   | };
374   |
375   | static inline void afi_writel(struct tegra_pcie *pcie, u32 value,
376   |  unsigned long offset)
377   | {
378   |  writel(value, pcie->afi + offset);
379   | }
380   |
381   | static inline u32 afi_readl(struct tegra_pcie *pcie, unsigned long offset)
382   | {
383   |  return readl(pcie->afi + offset);
384   | }
385   |
386   | static inline void pads_writel(struct tegra_pcie *pcie, u32 value,
387   |  unsigned long offset)
388   | {
389   |  writel(value, pcie->pads + offset);
390   | }
391   |
392   | static inline u32 pads_readl(struct tegra_pcie *pcie, unsigned long offset)
393   | {
394   |  return readl(pcie->pads + offset);
395   | }
396   |
397   | /*
398   |  * The configuration space mapping on Tegra is somewhat similar to the ECAM
399   |  * defined by PCIe. However it deviates a bit in how the 4 bits for extended
400   |  * register accesses are mapped:
401   |  *
402   |  *    [27:24] extended register number
403   |  *    [23:16] bus number
404   |  *    [15:11] device number
405   |  *    [10: 8] function number
406   |  *    [ 7: 0] register number
407   |  *
408   |  * Mapping the whole extended configuration space would require 256 MiB of
409   |  * virtual address space, only a small part of which will actually be used.
410   |  *
411   |  * To work around this, a 4 KiB region is used to generate the required
412   |  * configuration transaction with relevant B:D:F and register offset values.
413   |  * This is achieved by dynamically programming base address and size of
1038  |  if (err < 0)
1039  |  dev_err(dev, "failed to power on PHY: %d\n", err);
1040  |
1041  |  return err;
1042  | 	}
1043  |
1044  |  list_for_each_entry(port, &pcie->ports, list) {
1045  | 		err = tegra_pcie_port_phy_power_on(port);
1046  |  if (err < 0) {
1047  |  dev_err(dev,
1048  |  "failed to power on PCIe port %u PHY: %d\n",
1049  |  port->index, err);
1050  |  return err;
1051  | 		}
1052  | 	}
1053  |
1054  |  return 0;
1055  | }
1056  |
1057  | static int tegra_pcie_phy_power_off(struct tegra_pcie *pcie)
1058  | {
1059  |  struct device *dev = pcie->dev;
1060  |  struct tegra_pcie_port *port;
1061  |  int err;
1062  |
1063  |  if (pcie->legacy_phy) {
1064  |  if (pcie->phy)
1065  | 			err = phy_power_off(pcie->phy);
1066  |  else
1067  | 			err = tegra_pcie_phy_disable(pcie);
1068  |
1069  |  if (err < 0)
1070  |  dev_err(dev, "failed to power off PHY: %d\n", err);
1071  |
1072  |  return err;
1073  | 	}
1074  |
1075  |  list_for_each_entry(port, &pcie->ports, list) {
1076  | 		err = tegra_pcie_port_phy_power_off(port);
1077  |  if (err < 0) {
1078  |  dev_err(dev,
1079  |  "failed to power off PCIe port %u PHY: %d\n",
1080  |  port->index, err);
1081  |  return err;
1082  | 		}
1083  | 	}
1084  |
1085  |  return 0;
1086  | }
1087  |
1088  | static void tegra_pcie_enable_controller(struct tegra_pcie *pcie)
1089  | {
1090  |  const struct tegra_pcie_soc *soc = pcie->soc;
1091  |  struct tegra_pcie_port *port;
1092  |  unsigned long value;
1093  |
1094  |  /* enable PLL power down */
1095  |  if (pcie->phy) {
    6←Assuming field 'phy' is null→
    7←Taking false branch→
1096  | 		value = afi_readl(pcie, AFI_PLLE_CONTROL);
1097  | 		value &= ~AFI_PLLE_CONTROL_BYPASS_PADS2PLLE_CONTROL;
1098  | 		value |= AFI_PLLE_CONTROL_PADS2PLLE_CONTROL_EN;
1099  | 		afi_writel(pcie, value, AFI_PLLE_CONTROL);
1100  | 	}
1101  |
1102  |  /* power down PCIe slot clock bias pad */
1103  |  if (soc->has_pex_bias_ctrl)
    8←Assuming field 'has_pex_bias_ctrl' is false→
    9←Taking false branch→
1104  | 		afi_writel(pcie, 0, AFI_PEXBIAS_CTRL_0);
1105  |
1106  |  /* configure mode and disable all ports */
1107  |  value = afi_readl(pcie, AFI_PCIE_CONFIG);
1108  | 	value &= ~AFI_PCIE_CONFIG_SM2TMS0_XBAR_CONFIG_MASK;
1109  | 	value |= AFI_PCIE_CONFIG_PCIE_DISABLE_ALL | pcie->xbar_config;
1110  |  value |= AFI_PCIE_CONFIG_PCIE_CLKREQ_GPIO_ALL;
1111  |
1112  |  list_for_each_entry(port, &pcie->ports, list) {
    10←Loop condition is true.  Entering loop body→
1113  |  value &= ~AFI_PCIE_CONFIG_PCIE_DISABLE(port->index);
    11←Assuming right operand of bit shift is less than 32→
    12←Shift done in 32-bit, widened after; cast left operand to 64-bit before <<
1114  | 		value &= ~AFI_PCIE_CONFIG_PCIE_CLKREQ_GPIO(port->index);
1115  | 	}
1116  |
1117  | 	afi_writel(pcie, value, AFI_PCIE_CONFIG);
1118  |
1119  |  if (soc->has_gen2) {
1120  | 		value = afi_readl(pcie, AFI_FUSE);
1121  | 		value &= ~AFI_FUSE_PCIE_T0_GEN2_DIS;
1122  | 		afi_writel(pcie, value, AFI_FUSE);
1123  | 	} else {
1124  | 		value = afi_readl(pcie, AFI_FUSE);
1125  | 		value |= AFI_FUSE_PCIE_T0_GEN2_DIS;
1126  | 		afi_writel(pcie, value, AFI_FUSE);
1127  | 	}
1128  |
1129  |  /* Disable AFI dynamic clock gating and enable PCIe */
1130  | 	value = afi_readl(pcie, AFI_CONFIGURATION);
1131  | 	value |= AFI_CONFIGURATION_EN_FPCI;
1132  | 	value |= AFI_CONFIGURATION_CLKEN_OVERRIDE;
1133  | 	afi_writel(pcie, value, AFI_CONFIGURATION);
1134  |
1135  | 	value = AFI_INTR_EN_INI_SLVERR | AFI_INTR_EN_INI_DECERR |
1136  |  AFI_INTR_EN_TGT_SLVERR | AFI_INTR_EN_TGT_DECERR |
1137  |  AFI_INTR_EN_TGT_WRERR | AFI_INTR_EN_DFPCI_DECERR;
1138  |
1139  |  if (soc->has_intr_prsnt_sense)
1140  | 		value |= AFI_INTR_EN_PRSNT_SENSE;
1141  |
1142  | 	afi_writel(pcie, value, AFI_AFI_INTR_ENABLE);
1143  | 	afi_writel(pcie, 0xffffffff, AFI_SM_INTR_ENABLE);
2691  |
2692  | 	pci_stop_root_bus(host->bus);
2693  | 	pci_remove_root_bus(host->bus);
2694  | 	pm_runtime_put_sync(pcie->dev);
2695  | 	pm_runtime_disable(pcie->dev);
2696  |
2697  |  if (IS_ENABLED(CONFIG_PCI_MSI))
2698  | 		tegra_pcie_msi_teardown(pcie);
2699  |
2700  | 	tegra_pcie_put_resources(pcie);
2701  |
2702  |  list_for_each_entry_safe(port, tmp, &pcie->ports, list)
2703  | 		tegra_pcie_port_free(port);
2704  | }
2705  |
2706  | static int tegra_pcie_pm_suspend(struct device *dev)
2707  | {
2708  |  struct tegra_pcie *pcie = dev_get_drvdata(dev);
2709  |  struct tegra_pcie_port *port;
2710  |  int err;
2711  |
2712  |  list_for_each_entry(port, &pcie->ports, list)
2713  | 		tegra_pcie_pme_turnoff(port);
2714  |
2715  | 	tegra_pcie_disable_ports(pcie);
2716  |
2717  |  /*
2718  |  * AFI_INTR is unmasked in tegra_pcie_enable_controller(), mask it to
2719  |  * avoid unwanted interrupts raised by AFI after pex_rst is asserted.
2720  |  */
2721  | 	tegra_pcie_disable_interrupts(pcie);
2722  |
2723  |  if (pcie->soc->program_uphy) {
2724  | 		err = tegra_pcie_phy_power_off(pcie);
2725  |  if (err < 0)
2726  |  dev_err(dev, "failed to power off PHY(s): %d\n", err);
2727  | 	}
2728  |
2729  | 	reset_control_assert(pcie->pex_rst);
2730  | 	clk_disable_unprepare(pcie->pex_clk);
2731  |
2732  |  if (IS_ENABLED(CONFIG_PCI_MSI))
2733  | 		tegra_pcie_disable_msi(pcie);
2734  |
2735  | 	pinctrl_pm_select_idle_state(dev);
2736  | 	tegra_pcie_power_off(pcie);
2737  |
2738  |  return 0;
2739  | }
2740  |
2741  | static int tegra_pcie_pm_resume(struct device *dev)
2742  | {
2743  |  struct tegra_pcie *pcie = dev_get_drvdata(dev);
2744  |  int err;
2745  |
2746  | 	err = tegra_pcie_power_on(pcie);
2747  |  if (err) {
    1Assuming 'err' is 0→
    2←Taking false branch→
2748  |  dev_err(dev, "tegra pcie power on fail: %d\n", err);
2749  |  return err;
2750  | 	}
2751  |
2752  |  err = pinctrl_pm_select_default_state(dev);
2753  |  if (err < 0) {
    3←Assuming 'err' is >= 0→
    4←Taking false branch→
2754  |  dev_err(dev, "failed to disable PCIe IO DPD: %d\n", err);
2755  |  goto poweroff;
2756  | 	}
2757  |
2758  |  tegra_pcie_enable_controller(pcie);
    5←Calling 'tegra_pcie_enable_controller'→
2759  | 	tegra_pcie_setup_translations(pcie);
2760  |
2761  |  if (IS_ENABLED(CONFIG_PCI_MSI))
2762  | 		tegra_pcie_enable_msi(pcie);
2763  |
2764  | 	err = clk_prepare_enable(pcie->pex_clk);
2765  |  if (err) {
2766  |  dev_err(dev, "failed to enable PEX clock: %d\n", err);
2767  |  goto pex_dpd_enable;
2768  | 	}
2769  |
2770  | 	reset_control_deassert(pcie->pex_rst);
2771  |
2772  |  if (pcie->soc->program_uphy) {
2773  | 		err = tegra_pcie_phy_power_on(pcie);
2774  |  if (err < 0) {
2775  |  dev_err(dev, "failed to power on PHY(s): %d\n", err);
2776  |  goto disable_pex_clk;
2777  | 		}
2778  | 	}
2779  |
2780  | 	tegra_pcie_apply_pad_settings(pcie);
2781  | 	tegra_pcie_enable_ports(pcie);
2782  |
2783  |  return 0;
2784  |
2785  | disable_pex_clk:
2786  | 	reset_control_assert(pcie->pex_rst);
2787  | 	clk_disable_unprepare(pcie->pex_clk);
2788  | pex_dpd_enable:

Analysis:
- Decision: NotABug
- Reason: The flagged line uses a per-port mask macro inside a 32-bit register manipulation:
  - value is unsigned long but holds a u32 read from AFI_PCIE_CONFIG, and is later written back via afi_writel (u32). Only the low 32 bits are meaningful.
  - AFI_PCIE_CONFIG_PCIE_DISABLE(port->index) is a bitmask macro that shifts by a small amount (the analyzer itself assumes the shift count is less than 32). Even if the macro’s left operand were a 32-bit literal (e.g., 1U), shifting by <32 does not overflow 32 bits.
  - There is no assignment to u64 nor any further shift; the expression is just used as a 32-bit mask in a bitwise AND with value. On 64-bit builds, integer promotions will zero-extend the 32-bit mask to unsigned long; no bits are lost or miscomputed because the register width is 32 bits and value’s upper 32 bits are zero.
  - The target bug pattern requires a 32-bit shift whose result should extend beyond 32 bits and only widens to 64-bit after the shift, causing truncation. That is not the case here: the shift remains within 32-bit range and the operation domain is a 32-bit hardware register.
  - There is no corresponding fix patch changing this to a u64 cast, and such a cast would be unnecessary for a 32-bit register write.

Therefore, this report does not match the specified bug pattern and does not represent a real bug.

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
#include "llvm/ADT/StringRef.h"

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

  // Centralized FP gate
  static bool isFalsePositiveContext(const Expr *WholeExpr,
                                     const BinaryOperator *Shl,
                                     CheckerContext &C) {
    // Suppress if the shift isn't the top-level expression being assigned/returned/passed.
    if (!isTopLevelShiftExpr(WholeExpr, Shl))
      return true;

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
                                                   CheckerContext &C, StringRef) const {
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

  // Suppress known false-positive contexts.
  if (isFalsePositiveContext(E, Shl, C))
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
