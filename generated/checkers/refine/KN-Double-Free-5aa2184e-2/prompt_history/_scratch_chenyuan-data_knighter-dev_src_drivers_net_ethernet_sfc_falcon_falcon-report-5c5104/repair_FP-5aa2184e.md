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

File:| drivers/net/ethernet/sfc/falcon/falcon.c
---|---
Warning:| line 2421, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


1730  |  return 0;
1731  | }
1732  |
1733  | static void falcon_remove_port(struct ef4_nic *efx)
1734  | {
1735  | 	efx->phy_op->remove(efx);
1736  | 	ef4_nic_free_buffer(efx, &efx->stats_buffer);
1737  | }
1738  |
1739  | /* Global events are basically PHY events */
1740  | static bool
1741  | falcon_handle_global_event(struct ef4_channel *channel, ef4_qword_t *event)
1742  | {
1743  |  struct ef4_nic *efx = channel->efx;
1744  |  struct falcon_nic_data *nic_data = efx->nic_data;
1745  |
1746  |  if (EF4_QWORD_FIELD(*event, FSF_AB_GLB_EV_G_PHY0_INTR) ||
1747  |  EF4_QWORD_FIELD(*event, FSF_AB_GLB_EV_XG_PHY0_INTR) ||
1748  |  EF4_QWORD_FIELD(*event, FSF_AB_GLB_EV_XFP_PHY0_INTR))
1749  |  /* Ignored */
1750  |  return true;
1751  |
1752  |  if ((ef4_nic_rev(efx) == EF4_REV_FALCON_B0) &&
1753  |  EF4_QWORD_FIELD(*event, FSF_BB_GLB_EV_XG_MGT_INTR)) {
1754  | 		nic_data->xmac_poll_required = true;
1755  |  return true;
1756  | 	}
1757  |
1758  |  if (ef4_nic_rev(efx) <= EF4_REV_FALCON_A1 ?
1759  |  EF4_QWORD_FIELD(*event, FSF_AA_GLB_EV_RX_RECOVERY) :
1760  |  EF4_QWORD_FIELD(*event, FSF_BB_GLB_EV_RX_RECOVERY)) {
1761  |  netif_err(efx, rx_err, efx->net_dev,
1762  |  "channel %d seen global RX_RESET event. Resetting.\n",
1763  |  channel->channel);
1764  |
1765  | 		atomic_inc(&efx->rx_reset);
1766  | 		ef4_schedule_reset(efx, EF4_WORKAROUND_6555(efx) ?
1767  | 				   RESET_TYPE_RX_RECOVERY : RESET_TYPE_DISABLE);
1768  |  return true;
1769  | 	}
1770  |
1771  |  return false;
1772  | }
1773  |
1774  | /**************************************************************************
1775  |  *
1776  |  * Falcon test code
1777  |  *
1778  |  **************************************************************************/
1779  |
1780  | static int
1781  | falcon_read_nvram(struct ef4_nic *efx, struct falcon_nvconfig *nvconfig_out)
1782  | {
1783  |  struct falcon_nic_data *nic_data = efx->nic_data;
1784  |  struct falcon_nvconfig *nvconfig;
1785  |  struct falcon_spi_device *spi;
1786  |  void *region;
1787  |  int rc, magic_num, struct_ver;
1788  | 	__le16 *word, *limit;
1789  | 	u32 csum;
1790  |
1791  |  if (falcon_spi_present(&nic_data->spi_flash))
1792  | 		spi = &nic_data->spi_flash;
1793  |  else if (falcon_spi_present(&nic_data->spi_eeprom))
1794  | 		spi = &nic_data->spi_eeprom;
1795  |  else
1796  |  return -EINVAL;
1797  |
1798  | 	region = kmalloc(FALCON_NVCONFIG_END, GFP_KERNEL);
1799  |  if (!region)
1800  |  return -ENOMEM;
1801  | 	nvconfig = region + FALCON_NVCONFIG_OFFSET;
1802  |
1803  |  mutex_lock(&nic_data->spi_lock);
1804  | 	rc = falcon_spi_read(efx, spi, 0, FALCON_NVCONFIG_END, NULL, region);
1805  | 	mutex_unlock(&nic_data->spi_lock);
1806  |  if (rc) {
1807  |  netif_err(efx, hw, efx->net_dev, "Failed to read %s\n",
1808  |  falcon_spi_present(&nic_data->spi_flash) ?
1809  |  "flash" : "EEPROM");
1810  | 		rc = -EIO;
1811  |  goto out;
1812  | 	}
1813  |
1814  | 	magic_num = le16_to_cpu(nvconfig->board_magic_num);
1815  | 	struct_ver = le16_to_cpu(nvconfig->board_struct_ver);
1816  |
1817  | 	rc = -EINVAL;
1818  |  if (magic_num != FALCON_NVCONFIG_BOARD_MAGIC_NUM) {
1819  |  netif_err(efx, hw, efx->net_dev,
1820  |  "NVRAM bad magic 0x%x\n", magic_num);
1821  |  goto out;
1822  | 	}
1823  |  if (struct_ver < 2) {
1824  |  netif_err(efx, hw, efx->net_dev,
1825  |  "NVRAM has ancient version 0x%x\n", struct_ver);
1826  |  goto out;
2127  |
2128  |  /* Wait for SRAM reset to complete */
2129  | 	count = 0;
2130  |  do {
2131  |  netif_dbg(efx, hw, efx->net_dev,
2132  |  "waiting for SRAM reset (attempt %d)...\n", count);
2133  |
2134  |  /* SRAM reset is slow; expect around 16ms */
2135  | 		schedule_timeout_uninterruptible(HZ / 50);
2136  |
2137  |  /* Check for reset complete */
2138  | 		ef4_reado(efx, &srm_cfg_reg_ker, FR_AZ_SRM_CFG);
2139  |  if (!EF4_OWORD_FIELD(srm_cfg_reg_ker, FRF_AZ_SRM_INIT_EN)) {
2140  |  netif_dbg(efx, hw, efx->net_dev,
2141  |  "SRAM reset complete\n");
2142  |
2143  |  return 0;
2144  | 		}
2145  | 	} while (++count < 20);	/* wait up to 0.4 sec */
2146  |
2147  |  netif_err(efx, hw, efx->net_dev, "timed out waiting for SRAM reset\n");
2148  |  return -ETIMEDOUT;
2149  | }
2150  |
2151  | static void falcon_spi_device_init(struct ef4_nic *efx,
2152  |  struct falcon_spi_device *spi_device,
2153  |  unsigned int device_id, u32 device_type)
2154  | {
2155  |  if (device_type != 0) {
2156  | 		spi_device->device_id = device_id;
2157  | 		spi_device->size =
2158  | 			1 << SPI_DEV_TYPE_FIELD(device_type, SPI_DEV_TYPE_SIZE);
2159  | 		spi_device->addr_len =
2160  |  SPI_DEV_TYPE_FIELD(device_type, SPI_DEV_TYPE_ADDR_LEN);
2161  | 		spi_device->munge_address = (spi_device->size == 1 << 9 &&
2162  | 					     spi_device->addr_len == 1);
2163  | 		spi_device->erase_command =
2164  |  SPI_DEV_TYPE_FIELD(device_type, SPI_DEV_TYPE_ERASE_CMD);
2165  | 		spi_device->erase_size =
2166  | 			1 << SPI_DEV_TYPE_FIELD(device_type,
2167  |  SPI_DEV_TYPE_ERASE_SIZE);
2168  | 		spi_device->block_size =
2169  | 			1 << SPI_DEV_TYPE_FIELD(device_type,
2170  |  SPI_DEV_TYPE_BLOCK_SIZE);
2171  | 	} else {
2172  | 		spi_device->size = 0;
2173  | 	}
2174  | }
2175  |
2176  | /* Extract non-volatile configuration */
2177  | static int falcon_probe_nvconfig(struct ef4_nic *efx)
2178  | {
2179  |  struct falcon_nic_data *nic_data = efx->nic_data;
2180  |  struct falcon_nvconfig *nvconfig;
2181  |  int rc;
2182  |
2183  | 	nvconfig = kmalloc(sizeof(*nvconfig), GFP_KERNEL);
2184  |  if (!nvconfig)
2185  |  return -ENOMEM;
2186  |
2187  | 	rc = falcon_read_nvram(efx, nvconfig);
2188  |  if (rc)
2189  |  goto out;
2190  |
2191  | 	efx->phy_type = nvconfig->board_v2.port0_phy_type;
2192  | 	efx->mdio.prtad = nvconfig->board_v2.port0_phy_addr;
2193  |
2194  |  if (le16_to_cpu(nvconfig->board_struct_ver) >= 3) {
2195  | 		falcon_spi_device_init(
2196  | 			efx, &nic_data->spi_flash, FFE_AB_SPI_DEVICE_FLASH,
2197  |  le32_to_cpu(nvconfig->board_v3
2198  |  .spi_device_type[FFE_AB_SPI_DEVICE_FLASH]));
2199  | 		falcon_spi_device_init(
2200  | 			efx, &nic_data->spi_eeprom, FFE_AB_SPI_DEVICE_EEPROM,
2201  |  le32_to_cpu(nvconfig->board_v3
2202  |  .spi_device_type[FFE_AB_SPI_DEVICE_EEPROM]));
2203  | 	}
2204  |
2205  |  /* Read the MAC addresses */
2206  | 	ether_addr_copy(efx->net_dev->perm_addr, nvconfig->mac_address[0]);
2207  |
2208  |  netif_dbg(efx, probe, efx->net_dev, "PHY is %d phy_id %d\n",
2209  |  efx->phy_type, efx->mdio.prtad);
2210  |
2211  | 	rc = falcon_probe_board(efx,
2212  |  le16_to_cpu(nvconfig->board_v2.board_revision));
2213  | out:
2214  | 	kfree(nvconfig);
2215  |  return rc;
2216  | }
2217  |
2218  | static int falcon_dimension_resources(struct ef4_nic *efx)
2219  | {
2220  | 	efx->rx_dc_base = 0x20000;
2221  | 	efx->tx_dc_base = 0x26000;
2222  |  return 0;
2223  | }
2224  |
2225  | /* Probe all SPI devices on the NIC */
2226  | static void falcon_probe_spi_devices(struct ef4_nic *efx)
2227  | {
2228  |  struct falcon_nic_data *nic_data = efx->nic_data;
2229  | 	ef4_oword_t nic_stat, gpio_ctl, ee_vpd_cfg;
2230  |  int boot_dev;
2231  |
2232  | 	ef4_reado(efx, &gpio_ctl, FR_AB_GPIO_CTL);
2233  | 	ef4_reado(efx, &nic_stat, FR_AB_NIC_STAT);
2234  | 	ef4_reado(efx, &ee_vpd_cfg, FR_AB_EE_VPD_CFG0);
2235  |
2236  |  if (EF4_OWORD_FIELD(gpio_ctl, FRF_AB_GPIO3_PWRUP_VALUE)) {
2237  | 		boot_dev = (EF4_OWORD_FIELD(nic_stat, FRF_AB_SF_PRST) ?
2238  |  FFE_AB_SPI_DEVICE_FLASH : FFE_AB_SPI_DEVICE_EEPROM);
2239  |  netif_dbg(efx, probe, efx->net_dev, "Booted from %s\n",
2240  |  boot_dev == FFE_AB_SPI_DEVICE_FLASH ?
2241  |  "flash" : "EEPROM");
2242  | 	} else {
2243  |  /* Disable VPD and set clock dividers to safe
2244  |  * values for initial programming. */
2245  | 		boot_dev = -1;
2246  |  netif_dbg(efx, probe, efx->net_dev,
2247  |  "Booted from internal ASIC settings;"
2248  |  " setting SPI config\n");
2249  |  EF4_POPULATE_OWORD_3(ee_vpd_cfg, FRF_AB_EE_VPD_EN, 0,
2250  |  /* 125 MHz / 7 ~= 20 MHz */
2251  |  FRF_AB_EE_SF_CLOCK_DIV, 7,
2252  |  /* 125 MHz / 63 ~= 2 MHz */
2253  |  FRF_AB_EE_EE_CLOCK_DIV, 63);
2254  | 		ef4_writeo(efx, &ee_vpd_cfg, FR_AB_EE_VPD_CFG0);
2255  | 	}
2256  |
2257  |  mutex_init(&nic_data->spi_lock);
2258  |
2259  |  if (boot_dev == FFE_AB_SPI_DEVICE_FLASH)
2260  | 		falcon_spi_device_init(efx, &nic_data->spi_flash,
2261  |  FFE_AB_SPI_DEVICE_FLASH,
2262  | 				       default_flash_type);
2263  |  if (boot_dev == FFE_AB_SPI_DEVICE_EEPROM)
2264  | 		falcon_spi_device_init(efx, &nic_data->spi_eeprom,
2265  |  FFE_AB_SPI_DEVICE_EEPROM,
2266  | 				       large_eeprom_type);
2267  | }
2268  |
2269  | static unsigned int falcon_a1_mem_map_size(struct ef4_nic *efx)
2270  | {
2271  |  return 0x20000;
2272  | }
2273  |
2274  | static unsigned int falcon_b0_mem_map_size(struct ef4_nic *efx)
2275  | {
2276  |  /* Map everything up to and including the RSS indirection table.
2277  |  * The PCI core takes care of mapping the MSI-X tables.
2278  |  */
2279  |  return FR_BZ_RX_INDIRECTION_TBL +
2280  |  FR_BZ_RX_INDIRECTION_TBL_STEP * FR_BZ_RX_INDIRECTION_TBL_ROWS;
2281  | }
2282  |
2283  | static int falcon_probe_nic(struct ef4_nic *efx)
2284  | {
2285  |  struct falcon_nic_data *nic_data;
2286  |  struct falcon_board *board;
2287  |  int rc;
2288  |
2289  | 	efx->primary = efx; /* only one usable function per controller */
2290  |
2291  |  /* Allocate storage for hardware specific data */
2292  | 	nic_data = kzalloc(sizeof(*nic_data), GFP_KERNEL);
2293  |  if (!nic_data)
    1Assuming 'nic_data' is non-null→
    2←Taking false branch→
2294  |  return -ENOMEM;
2295  |  efx->nic_data = nic_data;
2296  | 	nic_data->efx = efx;
2297  |
2298  | 	rc = -ENODEV;
2299  |
2300  |  if (ef4_farch_fpga_ver(efx) != 0) {
    3←Assuming the condition is false→
    4←Taking false branch→
2301  |  netif_err(efx, probe, efx->net_dev,
2302  |  "Falcon FPGA not supported\n");
2303  |  goto fail1;
2304  | 	}
2305  |
2306  |  if (ef4_nic_rev(efx) <= EF4_REV_FALCON_A1) {
    5←Assuming the condition is false→
    6←Taking false branch→
2307  | 		ef4_oword_t nic_stat;
2308  |  struct pci_dev *dev;
2309  | 		u8 pci_rev = efx->pci_dev->revision;
2310  |
2311  |  if ((pci_rev == 0xff) || (pci_rev == 0)) {
2312  |  netif_err(efx, probe, efx->net_dev,
2313  |  "Falcon rev A0 not supported\n");
2314  |  goto fail1;
2315  | 		}
2316  | 		ef4_reado(efx, &nic_stat, FR_AB_NIC_STAT);
2317  |  if (EF4_OWORD_FIELD(nic_stat, FRF_AB_STRAP_10G) == 0) {
2318  |  netif_err(efx, probe, efx->net_dev,
2319  |  "Falcon rev A1 1G not supported\n");
2320  |  goto fail1;
2321  | 		}
2322  |  if (EF4_OWORD_FIELD(nic_stat, FRF_AA_STRAP_PCIE) == 0) {
2323  |  netif_err(efx, probe, efx->net_dev,
2324  |  "Falcon rev A1 PCI-X not supported\n");
2325  |  goto fail1;
2326  | 		}
2327  |
2328  | 		dev = pci_dev_get(efx->pci_dev);
2329  |  while ((dev = pci_get_device(PCI_VENDOR_ID_SOLARFLARE,
2330  |  PCI_DEVICE_ID_SOLARFLARE_SFC4000A_1,
2331  | 					     dev))) {
2332  |  if (dev->bus == efx->pci_dev->bus &&
2333  | 			    dev->devfn == efx->pci_dev->devfn + 1) {
2334  | 				nic_data->pci_dev2 = dev;
2335  |  break;
2336  | 			}
2337  | 		}
2338  |  if (!nic_data->pci_dev2) {
2339  |  netif_err(efx, probe, efx->net_dev,
2340  |  "failed to find secondary function\n");
2341  | 			rc = -ENODEV;
2342  |  goto fail2;
2343  | 		}
2344  | 	}
2345  |
2346  |  /* Now we can reset the NIC */
2347  |  rc = __falcon_reset_hw(efx, RESET_TYPE_ALL);
2348  |  if (rc) {
    7←Assuming 'rc' is 0→
    8←Taking false branch→
2349  |  netif_err(efx, probe, efx->net_dev, "failed to reset NIC\n");
2350  |  goto fail3;
2351  | 	}
2352  |
2353  |  /* Allocate memory for INT_KER */
2354  |  rc = ef4_nic_alloc_buffer(efx, &efx->irq_status, sizeof(ef4_oword_t),
2355  |  GFP_KERNEL);
2356  |  if (rc)
    9←Assuming 'rc' is 0→
    10←Taking false branch→
2357  |  goto fail4;
2358  |  BUG_ON(efx->irq_status.dma_addr & 0x0f);
    11←Assuming the condition is true→
    12←Taking false branch→
    13←Loop condition is false.  Exiting loop→
2359  |
2360  |  netif_dbg(efx, probe, efx->net_dev,
    14←Assuming the condition is false→
    15←Taking false branch→
    16←Loop condition is false.  Exiting loop→
2361  |  "INT_KER at %llx (virt %p phys %llx)\n",
2362  |  (u64)efx->irq_status.dma_addr,
2363  |  efx->irq_status.addr,
2364  |  (u64)virt_to_phys(efx->irq_status.addr));
2365  |
2366  |  falcon_probe_spi_devices(efx);
2367  |
2368  |  /* Read in the non-volatile configuration */
2369  | 	rc = falcon_probe_nvconfig(efx);
2370  |  if (rc16.1'rc' is -22) {
    17←Taking true branch→
2371  |  if (rc == -EINVAL)
    18←Taking true branch→
2372  |  netif_err(efx, probe, efx->net_dev, "NVRAM is invalid\n");
    19←Assuming the condition is false→
    20←Taking false branch→
    21←Loop condition is false.  Exiting loop→
2373  |  goto fail5;
    22←Control jumps to line 2412→
2374  | 	}
2375  |
2376  | 	efx->max_channels = (ef4_nic_rev(efx) <= EF4_REV_FALCON_A1 ? 4 :
2377  |  EF4_MAX_CHANNELS);
2378  | 	efx->max_tx_channels = efx->max_channels;
2379  | 	efx->timer_quantum_ns = 4968; /* 621 cycles */
2380  | 	efx->timer_max_ns = efx->type->timer_period_max *
2381  | 			    efx->timer_quantum_ns;
2382  |
2383  |  /* Initialise I2C adapter */
2384  | 	board = falcon_board(efx);
2385  | 	board->i2c_adap.owner = THIS_MODULE;
2386  | 	board->i2c_data = falcon_i2c_bit_operations;
2387  | 	board->i2c_data.data = efx;
2388  | 	board->i2c_adap.algo_data = &board->i2c_data;
2389  | 	board->i2c_adap.dev.parent = &efx->pci_dev->dev;
2390  |  strscpy(board->i2c_adap.name, "SFC4000 GPIO",
2391  |  sizeof(board->i2c_adap.name));
2392  | 	rc = i2c_bit_add_bus(&board->i2c_adap);
2393  |  if (rc)
2394  |  goto fail5;
2395  |
2396  | 	rc = falcon_board(efx)->type->init(efx);
2397  |  if (rc) {
2398  |  netif_err(efx, probe, efx->net_dev,
2399  |  "failed to initialise board\n");
2400  |  goto fail6;
2401  | 	}
2402  |
2403  | 	nic_data->stats_disable_count = 1;
2404  |  timer_setup(&nic_data->stats_timer, falcon_stats_timer_func, 0);
2405  |
2406  |  return 0;
2407  |
2408  |  fail6:
2409  | 	i2c_del_adapter(&board->i2c_adap);
2410  |  memset(&board->i2c_adap, 0, sizeof(board->i2c_adap));
2411  |  fail5:
2412  |  ef4_nic_free_buffer(efx, &efx->irq_status);
2413  |  fail4:
2414  |  fail3:
2415  |  if (nic_data->pci_dev2) {
    23←Assuming field 'pci_dev2' is null→
    24←Taking false branch→
2416  | 		pci_dev_put(nic_data->pci_dev2);
2417  | 		nic_data->pci_dev2 = NULL;
2418  | 	}
2419  |  fail2:
2420  |  fail1:
2421  |  kfree(efx->nic_data);
    25←Freeing unowned field in shared error label; possible double free
2422  |  return rc;
2423  | }
2424  |
2425  | static void falcon_init_rx_cfg(struct ef4_nic *efx)
2426  | {
2427  |  /* RX control FIFO thresholds (32 entries) */
2428  |  const unsigned ctrl_xon_thr = 20;
2429  |  const unsigned ctrl_xoff_thr = 25;
2430  | 	ef4_oword_t reg;
2431  |
2432  | 	ef4_reado(efx, ®, FR_AZ_RX_CFG);
2433  |  if (ef4_nic_rev(efx) <= EF4_REV_FALCON_A1) {
2434  |  /* Data FIFO size is 5.5K.  The RX DMA engine only
2435  |  * supports scattering for user-mode queues, but will
2436  |  * split DMA writes at intervals of RX_USR_BUF_SIZE
2437  |  * (32-byte units) even for kernel-mode queues.  We
2438  |  * set it to be so large that that never happens.
2439  |  */
2440  |  EF4_SET_OWORD_FIELD(reg, FRF_AA_RX_DESC_PUSH_EN, 0);
2441  |  EF4_SET_OWORD_FIELD(reg, FRF_AA_RX_USR_BUF_SIZE,
2442  |  (3 * 4096) >> 5);
2443  |  EF4_SET_OWORD_FIELD(reg, FRF_AA_RX_XON_MAC_TH, 512 >> 8);
2444  |  EF4_SET_OWORD_FIELD(reg, FRF_AA_RX_XOFF_MAC_TH, 2048 >> 8);
2445  |  EF4_SET_OWORD_FIELD(reg, FRF_AA_RX_XON_TX_TH, ctrl_xon_thr);
2446  |  EF4_SET_OWORD_FIELD(reg, FRF_AA_RX_XOFF_TX_TH, ctrl_xoff_thr);
2447  | 	} else {
2448  |  /* Data FIFO size is 80K; register fields moved */
2449  |  EF4_SET_OWORD_FIELD(reg, FRF_BZ_RX_DESC_PUSH_EN, 0);
2450  |  EF4_SET_OWORD_FIELD(reg, FRF_BZ_RX_USR_BUF_SIZE,
2451  |  EF4_RX_USR_BUF_SIZE >> 5);

Analysis:
- Decision: NotABug
- Reason: The flagged free is kfree(efx->nic_data) in falcon_probe_nic(). This function itself allocates nic_data via kzalloc and immediately assigns it to efx->nic_data before any goto to the shared error labels. If allocation fails, it returns -ENOMEM directly, so the error labels are only reachable after efx->nic_data was allocated by this function. None of the called helpers in the failing paths free efx->nic_data, and there is no earlier kfree of this field in the function. Thus, the cleanup at the shared error label frees memory owned and allocated by this function exactly once.

This does not match the target bug pattern, which concerns freeing callee-managed or conditionally allocated memory unconditionally in a shared error path (leading to double free). Here, the memory is not callee-managed; it is always owned by the caller when the error labels are used. Therefore, the report is a false positive and not a real bug.

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
#include "llvm/ADT/SmallPtrSet.h"
#include <memory>

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

  // Per-function: fields directly assigned from ANY function call within this function.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::SmallPtrSet<const FieldDecl*, 16>> FuncLocallySetByCallFields;

  // Per-function: for each label, keep the list of concrete goto statements targeting it.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>>> FuncLabelGotos;

  // Per-function: earliest source location where a given FieldDecl is assigned from a function call.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const FieldDecl*, SourceLocation>> FuncFieldFirstSetByCallLoc;

  // New: Per-function maps keyed by FieldDecl -> ParmVarDecl -> locations.
  using ParmToLocsMap = llvm::DenseMap<const ParmVarDecl*, llvm::SmallVector<SourceLocation, 4>>;
  using FieldParmLocsMap = llvm::DenseMap<const FieldDecl*, ParmToLocsMap>;

  // Locations of kfree-like calls on param-field.
  mutable llvm::DenseMap<const FunctionDecl*, FieldParmLocsMap> FuncFieldFreeLocs;
  // Locations of param-field = NULL (or 0).
  mutable llvm::DenseMap<const FunctionDecl*, FieldParmLocsMap> FuncFieldNullSetLocs;
  // Locations where param-field is assigned from allocator-like calls.
  mutable llvm::DenseMap<const FunctionDecl*, FieldParmLocsMap> FuncFieldAllocAssignLocs;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Freeing unowned field in shared error label; possible double free", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to perform case-insensitive substring search using lowercase conversion.
  static bool containsLower(StringRef Haystack, StringRef Needle) {
    std::string Lower = Haystack.lower();
    return StringRef(Lower).contains(Needle);
  }

  static bool isPointerType(QualType QT) {
    return QT->isPointerType() || QT->isAnyPointerType();
  }

  // Helper to collect labels, gotos, and fields locally assigned from function calls,
  // as well as free/nullset/allocator-assign locations per (param, field).
  struct FuncInfoCollector : public RecursiveASTVisitor<FuncInfoCollector> {
    CheckerContext &C;
    llvm::DenseMap<const LabelDecl *, const LabelStmt *> LabelMap;
    llvm::SmallVector<const GotoStmt *, 16> Gotos;
    llvm::SmallPtrSet<const FieldDecl*, 16> LocallySetByCallFields;
    llvm::DenseMap<const FieldDecl*, SourceLocation> FirstSetLoc;

    FieldParmLocsMap FreeLocs;
    FieldParmLocsMap NullSetLocs;
    FieldParmLocsMap AllocAssignLocs;

    FuncInfoCollector(CheckerContext &Ctx) : C(Ctx) {}

    static const Expr *ignoreCastsAndWrappers(const Expr *E) {
      if (!E) return nullptr;
      const Expr *Cur = E->IgnoreParenImpCasts();
      while (true) {
        if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
          if (UO->getOpcode() == UO_AddrOf || UO->getOpcode() == UO_Deref) {
            Cur = UO->getSubExpr()->IgnoreParenImpCasts();
            continue;
          }
        }
        if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Cur)) {
          Cur = ASE->getBase()->IgnoreParenImpCasts();
          continue;
        }
        break;
      }
      return Cur->IgnoreParenImpCasts();
    }

    static bool isExplicitNullExpr(const Expr *E) {
      if (!E) return false;
      E = E->IgnoreParenImpCasts();
      if (isa<GNUNullExpr>(E)) return true;
#if CLANG_VERSION_MAJOR >= 4
      if (isa<CXXNullPtrLiteralExpr>(E)) return true;
#endif
      if (const auto *IL = dyn_cast<IntegerLiteral>(E))
        return IL->getValue().isZero();
      return false;
    }

    static const MemberExpr* getMemberExprFromExpr(const Expr *E) {
      const Expr *S = ignoreCastsAndWrappers(E);
      return dyn_cast_or_null<MemberExpr>(S);
    }

    // Resolve base to a function parameter if possible.
    static const ParmVarDecl *getDirectBaseParam(const Expr *BaseE) {
      if (!BaseE) return nullptr;
      const Expr *E = BaseE;
      while (true) {
        E = E->IgnoreParenImpCasts();
        if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
          UnaryOperatorKind Op = UO->getOpcode();
          if (Op == UO_Deref || Op == UO_AddrOf) {
            E = UO->getSubExpr();
            continue;
          }
        }
        if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
          E = ASE->getBase();
          continue;
        }
        break;
      }
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        return dyn_cast<ParmVarDecl>(DRE->getDecl());
      }
      return nullptr;
    }

    static bool callExprLooksLikeAllocator(const CallExpr *CE, CheckerContext &C) {
      if (!CE)
        return false;

      static const char *AllocNames[] = {
          "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
          "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
          "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
      };

      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        StringRef Name = FD->getName();
        for (const char *N : AllocNames)
          if (Name.equals(N))
            return true;
      }

      // Fallback to source text substring match.
      for (const char *N : AllocNames) {
        if (ExprHasName(CE, N, C))
          return true;
      }
      return false;
    }

    static bool getFreeLikeArgIndex(const CallExpr *CE, unsigned &OutIdx) {
      OutIdx = 0;
      if (!CE) return false;
      const FunctionDecl *FD = CE->getDirectCallee();
      if (!FD) return false;
      StringRef Name = FD->getName();
      if (Name.equals("kfree") || Name.equals("kvfree") || Name.equals("vfree")) {
        if (CE->getNumArgs() >= 1) { OutIdx = 0; return true; }
      } else if (Name.equals("devm_kfree")) {
        if (CE->getNumArgs() >= 2) { OutIdx = 1; return true; }
      }
      return false;
    }

    bool VisitLabelStmt(const LabelStmt *LS) {
      if (const LabelDecl *LD = LS->getDecl())
        LabelMap[LD] = LS;
      return true;
    }

    bool VisitGotoStmt(const GotoStmt *GS) {
      Gotos.push_back(GS);
      return true;
    }

    bool VisitBinaryOperator(const BinaryOperator *BO) {
      if (!BO || !BO->isAssignmentOp())
        return true;

      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      // Track fields assigned from call expressions (potential allocators).
      if (const auto *ME = dyn_cast<MemberExpr>(LHS)) {
        const ValueDecl *VD = ME->getMemberDecl();
        if (const auto *FD = dyn_cast_or_null<FieldDecl>(VD)) {
          const ParmVarDecl *BaseP = getDirectBaseParam(ME->getBase());
          if (BaseP) {
            // NULL set tracking.
            if (isExplicitNullExpr(RHS)) {
              NullSetLocs[FD->getCanonicalDecl()][BaseP].push_back(BO->getBeginLoc());
            }
            // Allocator-assignment tracking.
            if (const auto *CE = dyn_cast<CallExpr>(RHS)) {
              if (callExprLooksLikeAllocator(CE, C)) {
                AllocAssignLocs[FD->getCanonicalDecl()][BaseP].push_back(BO->getBeginLoc());
              }
            }
          }
        }
      }

      // Existing tracking of "assigned from any call" for other heuristics.
      const auto *ME = dyn_cast<MemberExpr>(LHS);
      const auto *CE = dyn_cast<CallExpr>(RHS);
      if (!ME || !CE)
        return true;

      // Only consider assignments of pointer-typed fields from function calls.
      const ValueDecl *VD = ME->getMemberDecl();
      if (!VD)
        return true;
      QualType LT = VD->getType();
      if (!isPointerType(LT))
        return true;

      if (const auto *FD = dyn_cast<FieldDecl>(VD)) {
        const FieldDecl *CanonFD = FD->getCanonicalDecl();
        LocallySetByCallFields.insert(CanonFD);
        SourceLocation CurLoc = BO->getBeginLoc();
        auto It = FirstSetLoc.find(CanonFD);
        if (It == FirstSetLoc.end()) {
          FirstSetLoc[CanonFD] = CurLoc;
        } else {
          const SourceManager &SM = C.getSourceManager();
          if (SM.isBeforeInTranslationUnit(CurLoc, It->second))
            It->second = CurLoc;
        }
      }
      return true;
    }

    bool VisitCallExpr(const CallExpr *CE) {
      unsigned ArgIdx = 0;
      if (!getFreeLikeArgIndex(CE, ArgIdx))
        return true;

      if (ArgIdx >= CE->getNumArgs())
        return true;

      const Expr *ArgE = CE->getArg(ArgIdx);
      const MemberExpr *ME = getMemberExprFromExpr(ArgE);
      if (!ME)
        return true;

      const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
      if (!FD)
        return true;

      const ParmVarDecl *BaseP = getDirectBaseParam(ME->getBase());
      if (!BaseP)
        return true;

      FreeLocs[FD->getCanonicalDecl()][BaseP].push_back(CE->getBeginLoc());
      return true;
    }
  };

  const FunctionDecl *getCurrentFunction(const CheckerContext &C) const {
    const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return D;
  }

  void buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const;

  bool isAllocatorCall(const CallEvent &Call, CheckerContext &C) const;

  // Identify free-like functions and which parameter indices are the freed pointers.
  bool getFreeLikeParamIndices(const CallEvent &Call,
                               llvm::SmallVectorImpl<unsigned> &Idxs) const;

  // Returns true if the reported scenario is a false positive and should be suppressed.
  bool isFalsePositive(const Expr *FreedArgE, const MemberExpr *FreedME,
                       const ParmVarDecl *BaseParam,
                       const CallEvent &Call, const LabelStmt *EnclosingLabel,
                       CheckerContext &C) const;

  // Gating heuristic: return the ParmVarDecl if the base of a MemberExpr resolves directly to a function parameter.
  const ParmVarDecl *getDirectBaseParam(const Expr *BaseE) const;

  // Additional gating: check whether the target label has any error-like incoming goto.
  bool labelHasErrorishIncoming(const FunctionDecl *FD, const LabelStmt *LS, CheckerContext &C) const;

  // Helpers for "error-ish" classification.
  bool labelNameLooksErrorish(const LabelStmt *LS) const;
  bool gotoLooksErrorish(const GotoStmt *GS, CheckerContext &C) const;
  bool condLooksErrorish(const Expr *Cond, CheckerContext &C) const;
  const Expr *stripWrapperCalls(const Expr *E, CheckerContext &C) const;

  void reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const {
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  FuncInfoCollector Collector(C);
  Collector.TraverseStmt(const_cast<Stmt *>(Body));

  // Build incoming goto counts and per-label goto lists.
  llvm::DenseMap<const LabelStmt*, unsigned> IncomingCount;
  llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>> LabelToGotos;
  for (const GotoStmt *GS : Collector.Gotos) {
    const LabelDecl *LD = GS->getLabel();
    if (!LD)
      continue;
    auto It = Collector.LabelMap.find(LD);
    if (It == Collector.LabelMap.end())
      continue;
    const LabelStmt *LS = It->second;
    IncomingCount[LS] = IncomingCount.lookup(LS) + 1;
    LabelToGotos[LS].push_back(GS);
  }

  FuncLabelIncoming[FD] = std::move(IncomingCount);
  FuncLocallySetByCallFields[FD] = std::move(Collector.LocallySetByCallFields);
  FuncLabelGotos[FD] = std::move(LabelToGotos);

  // Store earliest assignment-from-call locations for fields.
  llvm::DenseMap<const FieldDecl*, SourceLocation> Earliest;
  for (const auto &P : Collector.FirstSetLoc) {
    Earliest[P.first->getCanonicalDecl()] = P.second;
  }
  FuncFieldFirstSetByCallLoc[FD] = std::move(Earliest);

  // Store fine-grained per-(param,field) location data for FP suppression.
  FuncFieldFreeLocs[FD] = std::move(Collector.FreeLocs);
  FuncFieldNullSetLocs[FD] = std::move(Collector.NullSetLocs);
  FuncFieldAllocAssignLocs[FD] = std::move(Collector.AllocAssignLocs);
}

bool SAGenTestChecker::isAllocatorCall(const CallEvent &Call, CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;
  StringRef Name = FD->getName();

  static const char *Names[] = {
      "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
      "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
      "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
  };
  for (const char *N : Names) {
    if (Name.equals(N))
      return true;
  }
  return false;
}

bool SAGenTestChecker::getFreeLikeParamIndices(const CallEvent &Call,
                                               llvm::SmallVectorImpl<unsigned> &Idxs) const {
  Idxs.clear();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;

  StringRef Name = FD->getName();
  // Exact matches only; avoid substring matches like "devm_kfree" triggering "kfree".
  if (Name.equals("kfree") || Name.equals("kvfree") || Name.equals("vfree")) {
    if (Call.getNumArgs() >= 1)
      Idxs.push_back(0);
  } else if (Name.equals("devm_kfree")) {
    if (Call.getNumArgs() >= 2)
      Idxs.push_back(1); // freed pointer is the second argument
  } else {
    return false;
  }
  return !Idxs.empty();
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Build per-function metadata (labels and locally-assigned-from-call fields).
  buildPerFunctionInfo(FD, C);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Clean per-function metadata.
  FuncLabelIncoming.erase(FD);
  FuncLocallySetByCallFields.erase(FD);
  FuncLabelGotos.erase(FD);
  FuncFieldFirstSetByCallLoc.erase(FD);
  FuncFieldFreeLocs.erase(FD);
  FuncFieldNullSetLocs.erase(FD);
  FuncFieldAllocAssignLocs.erase(FD);
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

  SymbolRef RHSym = Val.getAsSymbol();
  if (!RHSym)
    return;

  if (State->contains<AllocSymSet>(RHSym)) {
    // Mark the precise region as owned.
    if (!State->contains<OwnedRegionSet>(DstReg)) {
      State = State->add<OwnedRegionSet>(DstReg);
    }
    // Also mark the base region to be robust against field/base conversions.
    const MemRegion *Base = DstReg->getBaseRegion();
    if (Base && !State->contains<OwnedRegionSet>(Base)) {
      State = State->add<OwnedRegionSet>(Base);
    }
    C.addTransition(State);
  }
}

const ParmVarDecl *SAGenTestChecker::getDirectBaseParam(const Expr *BaseE) const {
  if (!BaseE)
    return nullptr;

  const Expr *E = BaseE;
  while (true) {
    E = E->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      UnaryOperatorKind Op = UO->getOpcode();
      if (Op == UO_Deref || Op == UO_AddrOf) {
        E = UO->getSubExpr();
        continue;
      }
    }
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
      E = ASE->getBase();
      continue;
    }
    break;
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<ParmVarDecl>(DRE->getDecl());
  }
  return nullptr;
}

const Expr *SAGenTestChecker::stripWrapperCalls(const Expr *E, CheckerContext &C) const {
  const Expr *Cur = E ? E->IgnoreParenImpCasts() : nullptr;
  while (const auto *CE = dyn_cast_or_null<CallExpr>(Cur)) {
    const FunctionDecl *FD = CE->getDirectCallee();
    StringRef Name = FD ? FD->getName() : StringRef();
    // Common kernel wrappers/macros lowered as calls we want to peel.
    if (Name.equals("unlikely") || Name.equals("likely") ||
        Name.equals("__builtin_expect")) {
      if (CE->getNumArgs() > 0) {
        Cur = CE->getArg(0)->IgnoreParenImpCasts();
        continue;
      }
    }
    break;
  }
  return Cur ? Cur->IgnoreParenImpCasts() : nullptr;
}

bool SAGenTestChecker::condLooksErrorish(const Expr *Cond, CheckerContext &C) const {
  if (!Cond)
    return false;

  const Expr *E = stripWrapperCalls(Cond, C);
  if (!E)
    return false;

  // if (ret) or if (!ret) patterns where 'ret' is a typical error code variable.
  auto LooksLikeErrVar = [](StringRef N) {
    return N.equals("ret") || N.equals("rc") || N.equals("err") || N.equals("error") || N.equals("status");
  };

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (LooksLikeErrVar(VD->getName()))
        return true;
    }
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      if (const auto *D = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts()))
        if (const auto *VD = dyn_cast<VarDecl>(D->getDecl()))
          if (LooksLikeErrVar(VD->getName()))
            return true;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->isComparisonOp() || BO->getOpcode() == BO_NE || BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      auto IsZeroOrNegConst = [](const Expr *X) -> bool {
        if (const auto *IL = dyn_cast<IntegerLiteral>(X)) {
          return IL->getValue().isZero(); // zero
        }
        return false;
      };
      auto IsErrVar = [&](const Expr *X) -> bool {
        if (const auto *DR = dyn_cast<DeclRefExpr>(X))
          if (const auto *VD = dyn_cast<VarDecl>(DR->getDecl()))
            return LooksLikeErrVar(VD->getName());
        return false;
      };
      // ret != 0, ret < 0, 0 != ret, etc.
      if ((IsErrVar(L) && IsZeroOrNegConst(R)) || (IsErrVar(R) && IsZeroOrNegConst(L)))
        return true;
    }
  }

  // if (IS_ERR(ptr)) or IS_ERR_OR_NULL(ptr)
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      StringRef N = FD->getName();
      if (N.equals("IS_ERR") || N.equals("IS_ERR_OR_NULL") || N.equals("IS_ERR_VALUE"))
        return true;
    } else {
      // Fallback: text search in the expression for kernel helpers.
      if (ExprHasName(E, "IS_ERR", C) || ExprHasName(E, "IS_ERR_OR_NULL", C) || ExprHasName(E, "IS_ERR_VALUE", C))
        return true;
    }
  }

  return false;
}

bool SAGenTestChecker::labelNameLooksErrorish(const LabelStmt *LS) const {
  if (!LS || !LS->getDecl())
    return false;
  StringRef N = LS->getDecl()->getName();
  // Common error cleanup labels in kernel code.
  return containsLower(N, "err") || containsLower(N, "error") ||
         containsLower(N, "fail") || containsLower(N, "free") ||
         containsLower(N, "cleanup") || containsLower(N, "out_err");
}

bool SAGenTestChecker::gotoLooksErrorish(const GotoStmt *GS, CheckerContext &C) const {
  if (!GS)
    return false;

  // If there's an enclosing if-statement, examine its condition.
  if (const IfStmt *IS = findSpecificTypeInParents<IfStmt>(GS, C)) {
    if (const Expr *Cond = IS->getCond()) {
      if (condLooksErrorish(Cond, C))
        return true;
    }
  }

  // Otherwise, fall back to label name being errorish.
  const LabelDecl *LD = GS->getLabel();
  if (LD) {
    StringRef N = LD->getName();
    if (containsLower(N, "err") || containsLower(N, "error") ||
        containsLower(N, "fail") || containsLower(N, "free") ||
        containsLower(N, "cleanup") || containsLower(N, "out_err"))
      return true;
  }
  return false;
}

bool SAGenTestChecker::labelHasErrorishIncoming(const FunctionDecl *FD, const LabelStmt *LS, CheckerContext &C) const {
  if (!FD || !LS)
    return false;
  auto ItF = FuncLabelGotos.find(FD);
  if (ItF == FuncLabelGotos.end())
    return false;
  auto It = ItF->second.find(LS);
  if (It == ItF->second.end())
    return false;

  // If label name looks errorish, that's sufficient.
  if (labelNameLooksErrorish(LS))
    return true;

  const auto &Gotos = It->second;
  for (const GotoStmt *GS : Gotos) {
    if (gotoLooksErrorish(GS, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isFalsePositive(const Expr *FreedArgE,
                                       const MemberExpr *FreedME,
                                       const ParmVarDecl *BaseParam,
                                       const CallEvent &Call,
                                       const LabelStmt *EnclosingLabel,
                                       CheckerContext &C) const {
  // 0) If the label does not look like an error path for any of its incoming gotos,
  //    this is very likely a normal cleanup label (e.g. "out") -> suppress.
  const FunctionDecl *FD = getCurrentFunction(C);
  if (FD && EnclosingLabel && !labelHasErrorishIncoming(FD, EnclosingLabel, C))
    return true;

  // 1) If the argument is definitely the literal NULL at this point, kfree(NULL) is a no-op.
  if (FreedArgE) {
    SVal ArgVal = C.getSVal(FreedArgE);
    if (ArgVal.isZeroConstant())
      return true;
  }

  // 2) If this function path-sensitively owns the region (or its base), don't warn on this path.
  if (FreedArgE) {
    const MemRegion *FreedReg = getMemRegionFromExpr(FreedArgE, C);
    if (FreedReg) {
      const MemRegion *Base = FreedReg->getBaseRegion();
      ProgramStateRef State = C.getState();
      if (State->contains<OwnedRegionSet>(FreedReg) ||
          (Base && State->contains<OwnedRegionSet>(Base))) {
        return true;
      }
    }
  }

  // 2.5) Intrafunction allocator-assignment suppression:
  // If this same param-field was assigned from an allocator in this function
  // before the current free call, treat it as locally-owned and suppress.
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItAllocF = FuncFieldAllocAssignLocs.find(FD);
      if (ItAllocF != FuncFieldAllocAssignLocs.end()) {
        const auto &AllocMapField = ItAllocF->second;
        auto ItAllocParmMap = AllocMapField.find(CanonFD);
        if (ItAllocParmMap != AllocMapField.end()) {
          auto ItLocs = ItAllocParmMap->second.find(BaseParam);
          if (ItLocs != ItAllocParmMap->second.end()) {
            const llvm::SmallVector<SourceLocation,4> &AllocLocs = ItLocs->second;
            if (!AllocLocs.empty()) {
              const SourceManager &SM = C.getSourceManager();
              SourceLocation CurLoc = Call.getOriginExpr()
                                          ? Call.getOriginExpr()->getBeginLoc()
                                          : Call.getSourceRange().getBegin();
              for (SourceLocation Lalloc : AllocLocs) {
                if (SM.isBeforeInTranslationUnit(Lalloc, CurLoc)) {
                  return true;
                }
              }
            }
          }
        }
      }
    }
  }

  // 3) AST-based suppression for the "reset and reallocate" idiom:
  //    If there exists a prior free(field) followed by field = NULL (or 0) and then
  //    an allocator assignment to the same field, all before this free -> suppress.
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItFreeF = FuncFieldFreeLocs.find(FD);
      auto ItNullF = FuncFieldNullSetLocs.find(FD);
      auto ItAllocF = FuncFieldAllocAssignLocs.find(FD);
      if (ItFreeF != FuncFieldFreeLocs.end() &&
          ItNullF != FuncFieldNullSetLocs.end() &&
          ItAllocF != FuncFieldAllocAssignLocs.end()) {

        const auto &FreeMapField = ItFreeF->second;
        const auto &NullMapField = ItNullF->second;
        const auto &AllocMapField = ItAllocF->second;

        auto ItFreeParmMap  = FreeMapField.find(CanonFD);
        auto ItNullParmMap  = NullMapField.find(CanonFD);
        auto ItAllocParmMap = AllocMapField.find(CanonFD);

        if (ItFreeParmMap != FreeMapField.end() &&
            ItNullParmMap != NullMapField.end() &&
            ItAllocParmMap != AllocMapField.end()) {
          const auto &FreeVec  = ItFreeParmMap->second.lookup(BaseParam);
          const auto &NullVec  = ItNullParmMap->second.lookup(BaseParam);
          const auto &AllocVec = ItAllocParmMap->second.lookup(BaseParam);

          if (!FreeVec.empty() && !NullVec.empty() && !AllocVec.empty()) {
            const SourceManager &SM = C.getSourceManager();
            SourceLocation CurLoc = Call.getOriginExpr()
                                        ? Call.getOriginExpr()->getBeginLoc()
                                        : Call.getSourceRange().getBegin();
            // Check for free < null < alloc < current
            for (SourceLocation Lfree : FreeVec) {
              if (!SM.isBeforeInTranslationUnit(Lfree, CurLoc))
                continue;
              for (SourceLocation Lnull : NullVec) {
                if (!SM.isBeforeInTranslationUnit(Lfree, Lnull))
                  continue;
                if (!SM.isBeforeInTranslationUnit(Lnull, CurLoc))
                  continue;
                bool HasAllocBetween = false;
                for (SourceLocation Lalloc : AllocVec) {
                  if (SM.isBeforeInTranslationUnit(Lnull, Lalloc) &&
                      SM.isBeforeInTranslationUnit(Lalloc, CurLoc)) {
                    HasAllocBetween = true;
                    break;
                  }
                }
                if (HasAllocBetween) {
                  // All three conditions satisfied for this path -> suppress.
                  return true;
                }
              }
            }
          }
        }
      }
    }
  }

  return false;
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
  llvm::SmallVector<unsigned, 4> FreeIdxs;
  if (!getFreeLikeParamIndices(Call, FreeIdxs))
    return;

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

  // Only consider shared labels (2 or more incoming gotos).
  if (Count < 2)
    return;

  // Only consider labels that look like error paths.
  if (!labelHasErrorishIncoming(FD, EnclosingLabel, C))
    return;

  // Check each freed argument.
  for (unsigned ArgIndex : FreeIdxs) {
    const Expr *ArgE = Call.getArgExpr(ArgIndex);
    if (!ArgE)
      continue;

    // Only consider freeing a struct/union field like mt->fc.
    const Expr *Stripped = ArgE->IgnoreParenImpCasts();
    const auto *FreedME = dyn_cast<MemberExpr>(Stripped);
    if (!FreedME)
      continue;

    // Only warn when the freed field belongs directly to a function parameter.
    // This matches the target buggy pattern (e.g., mt->fc) and suppresses cleanup of local/private state.
    const Expr *BaseE = FreedME->getBase();
    const ParmVarDecl *BaseParam = getDirectBaseParam(BaseE);
    if (!BaseParam)
      continue;

    // Suppress known false positives (ownership known on path, non-error labels, or reset+realloc/local-alloc idioms).
    if (isFalsePositive(ArgE, FreedME, BaseParam, Call, EnclosingLabel, C))
      continue;

    reportFreeUnownedInSharedLabel(Call, C);
    // One report per call site is sufficient.
    return;
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
