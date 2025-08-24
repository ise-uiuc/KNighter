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

Allocating/initializing an HWRM request with hwrm_req_init() and then, on a subsequent failure (e.g., hwrm_req_replace() error), returning without calling hwrm_req_drop() to release the request buffer.

Pattern example:
rc = hwrm_req_init(bp, req, ...);
if (rc)
    return rc;

rc = hwrm_req_replace(bp, req, ...);
if (rc)
    return rc;  // BUG: missing hwrm_req_drop(bp, req) -> leak

Any exit after a successful hwrm_req_init() must call hwrm_req_drop(); missing this cleanup on error paths causes a memory leak.

The patch that needs to be detected:

## Patch Description

bnxt_en: Fix possible memory leak when hwrm_req_replace fails

When hwrm_req_replace() fails, the driver is not invoking bnxt_req_drop()
which could cause a memory leak.

Fixes: bbf33d1d9805 ("bnxt_en: update all firmware calls to use the new APIs")
Reviewed-by: Pavan Chebbi <pavan.chebbi@broadcom.com>
Signed-off-by: Kalesh AP <kalesh-anakkur.purayil@broadcom.com>
Signed-off-by: Michael Chan <michael.chan@broadcom.com>
Link: https://patch.msgid.link/20250104043849.3482067-2-michael.chan@broadcom.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>

## Buggy Code

```c
// Function: bnxt_send_msg in drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c
int bnxt_send_msg(struct bnxt_en_dev *edev,
			 struct bnxt_fw_msg *fw_msg)
{
	struct net_device *dev = edev->net;
	struct bnxt *bp = netdev_priv(dev);
	struct output *resp;
	struct input *req;
	u32 resp_len;
	int rc;

	if (bp->fw_reset_state)
		return -EBUSY;

	rc = hwrm_req_init(bp, req, 0 /* don't care */);
	if (rc)
		return rc;

	rc = hwrm_req_replace(bp, req, fw_msg->msg, fw_msg->msg_len);
	if (rc)
		return rc;

	hwrm_req_timeout(bp, req, fw_msg->timeout);
	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	resp_len = le16_to_cpu(resp->resp_len);
	if (resp_len) {
		if (fw_msg->resp_max_len < resp_len)
			resp_len = fw_msg->resp_max_len;

		memcpy(fw_msg->resp, resp, resp_len);
	}
	hwrm_req_drop(bp, req);
	return rc;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c b/drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c
index b771c84cdd89..0ed26e3a28f4 100644
--- a/drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c
+++ b/drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c
@@ -208,7 +208,7 @@ int bnxt_send_msg(struct bnxt_en_dev *edev,

 	rc = hwrm_req_replace(bp, req, fw_msg->msg, fw_msg->msg_len);
 	if (rc)
-		return rc;
+		goto drop_req;

 	hwrm_req_timeout(bp, req, fw_msg->timeout);
 	resp = hwrm_req_hold(bp, req);
@@ -220,6 +220,7 @@ int bnxt_send_msg(struct bnxt_en_dev *edev,

 		memcpy(fw_msg->resp, resp, resp_len);
 	}
+drop_req:
 	hwrm_req_drop(bp, req);
 	return rc;
 }
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/./include/linux/bitmap.h
---|---
Warning:| line 334, column 2
Missing hwrm_req_drop() after successful hwrm_req_init()

### Annotated Source Code


2344  | 			link_info->req_signal_mode = BNXT_SIG_MODE_PAM4;
2345  |  break;
2346  |  case BNXT_LINK_SPEED_100GB_PAM4_112:
2347  |  case BNXT_LINK_SPEED_200GB_PAM4_112:
2348  |  case BNXT_LINK_SPEED_400GB_PAM4_112:
2349  | 			link_info->req_signal_mode = BNXT_SIG_MODE_PAM4_112;
2350  |  break;
2351  |  default:
2352  | 			link_info->req_signal_mode = BNXT_SIG_MODE_NRZ;
2353  | 		}
2354  |  return;
2355  | 	}
2356  | 	link_info->req_link_speed = link_info->force_link_speed;
2357  | 	link_info->req_signal_mode = BNXT_SIG_MODE_NRZ;
2358  |  if (link_info->force_pam4_link_speed) {
2359  | 		link_info->req_link_speed = link_info->force_pam4_link_speed;
2360  | 		link_info->req_signal_mode = BNXT_SIG_MODE_PAM4;
2361  | 	}
2362  | }
2363  |
2364  | static void bnxt_set_auto_speed(struct bnxt_link_info *link_info)
2365  | {
2366  |  struct bnxt *bp = container_of(link_info, struct bnxt, link_info);
2367  |
2368  |  if (bp->phy_flags & BNXT_PHY_FL_SPEEDS2) {
2369  | 		link_info->advertising = link_info->auto_link_speeds2;
2370  |  return;
2371  | 	}
2372  | 	link_info->advertising = link_info->auto_link_speeds;
2373  | 	link_info->advertising_pam4 = link_info->auto_pam4_link_speeds;
2374  | }
2375  |
2376  | static bool bnxt_force_speed_updated(struct bnxt_link_info *link_info)
2377  | {
2378  |  struct bnxt *bp = container_of(link_info, struct bnxt, link_info);
2379  |
2380  |  if (bp->phy_flags & BNXT_PHY_FL_SPEEDS2) {
2381  |  if (link_info->req_link_speed != link_info->force_link_speed2)
2382  |  return true;
2383  |  return false;
2384  | 	}
2385  |  if (link_info->req_signal_mode == BNXT_SIG_MODE_NRZ &&
2386  | 	    link_info->req_link_speed != link_info->force_link_speed)
2387  |  return true;
2388  |  if (link_info->req_signal_mode == BNXT_SIG_MODE_PAM4 &&
2389  | 	    link_info->req_link_speed != link_info->force_pam4_link_speed)
2390  |  return true;
2391  |  return false;
2392  | }
2393  |
2394  | static bool bnxt_auto_speed_updated(struct bnxt_link_info *link_info)
2395  | {
2396  |  struct bnxt *bp = container_of(link_info, struct bnxt, link_info);
2397  |
2398  |  if (bp->phy_flags & BNXT_PHY_FL_SPEEDS2) {
2399  |  if (link_info->advertising != link_info->auto_link_speeds2)
2400  |  return true;
2401  |  return false;
2402  | 	}
2403  |  if (link_info->advertising != link_info->auto_link_speeds ||
2404  | 	    link_info->advertising_pam4 != link_info->auto_pam4_link_speeds)
2405  |  return true;
2406  |  return false;
2407  | }
2408  |
2409  | #define BNXT_EVENT_THERMAL_CURRENT_TEMP(data2)				\
2410  |  ((data2) &							\
2411  |  ASYNC_EVENT_CMPL_ERROR_REPORT_THERMAL_EVENT_DATA2_CURRENT_TEMP_MASK)
2412  |
2413  | #define BNXT_EVENT_THERMAL_THRESHOLD_TEMP(data2)			\
2414  |  (((data2) &							\
2415  |  ASYNC_EVENT_CMPL_ERROR_REPORT_THERMAL_EVENT_DATA2_THRESHOLD_TEMP_MASK) >>\
2416  |  ASYNC_EVENT_CMPL_ERROR_REPORT_THERMAL_EVENT_DATA2_THRESHOLD_TEMP_SFT)
2417  |
2418  | #define EVENT_DATA1_THERMAL_THRESHOLD_TYPE(data1)			\
2419  |  ((data1) &							\
2420  |  ASYNC_EVENT_CMPL_ERROR_REPORT_THERMAL_EVENT_DATA1_THRESHOLD_TYPE_MASK)
2421  |
2422  | #define EVENT_DATA1_THERMAL_THRESHOLD_DIR_INCREASING(data1)		\
2423  |  (((data1) &							\
2424  |  ASYNC_EVENT_CMPL_ERROR_REPORT_THERMAL_EVENT_DATA1_TRANSITION_DIR) ==\
2425  |  ASYNC_EVENT_CMPL_ERROR_REPORT_THERMAL_EVENT_DATA1_TRANSITION_DIR_INCREASING)
2426  |
2427  | /* Return true if the workqueue has to be scheduled */
2428  | static bool bnxt_event_error_report(struct bnxt *bp, u32 data1, u32 data2)
2429  | {
2430  | 	u32 err_type = BNXT_EVENT_ERROR_REPORT_TYPE(data1);
2431  |
10835 |  le16_to_cpu(resp->supported_speeds_auto_mode);
10836 |  if (resp->supported_pam4_speeds_auto_mode)
10837 | 		link_info->support_pam4_auto_speeds =
10838 |  le16_to_cpu(resp->supported_pam4_speeds_auto_mode);
10839 |  if (resp->supported_speeds2_auto_mode)
10840 | 		link_info->support_auto_speeds2 =
10841 |  le16_to_cpu(resp->supported_speeds2_auto_mode);
10842 |
10843 | 	bp->port_count = resp->port_cnt;
10844 |
10845 | hwrm_phy_qcaps_exit:
10846 | 	hwrm_req_drop(bp, req);
10847 |  return rc;
10848 | }
10849 |
10850 | static bool bnxt_support_dropped(u16 advertising, u16 supported)
10851 | {
10852 | 	u16 diff = advertising ^ supported;
10853 |
10854 |  return ((supported | diff) != supported);
10855 | }
10856 |
10857 | static bool bnxt_support_speed_dropped(struct bnxt_link_info *link_info)
10858 | {
10859 |  struct bnxt *bp = container_of(link_info, struct bnxt, link_info);
10860 |
10861 |  /* Check if any advertised speeds are no longer supported. The caller
10862 |  * holds the link_lock mutex, so we can modify link_info settings.
10863 |  */
10864 |  if (bp->phy_flags & BNXT_PHY_FL_SPEEDS2) {
10865 |  if (bnxt_support_dropped(link_info->advertising,
10866 | 					 link_info->support_auto_speeds2)) {
10867 | 			link_info->advertising = link_info->support_auto_speeds2;
10868 |  return true;
10869 | 		}
10870 |  return false;
10871 | 	}
10872 |  if (bnxt_support_dropped(link_info->advertising,
10873 | 				 link_info->support_auto_speeds)) {
10874 | 		link_info->advertising = link_info->support_auto_speeds;
10875 |  return true;
10876 | 	}
10877 |  if (bnxt_support_dropped(link_info->advertising_pam4,
10878 | 				 link_info->support_pam4_auto_speeds)) {
10879 | 		link_info->advertising_pam4 = link_info->support_pam4_auto_speeds;
10880 |  return true;
10881 | 	}
10882 |  return false;
10883 | }
10884 |
10885 | int bnxt_update_link(struct bnxt *bp, bool chng_link_state)
10886 | {
10887 |  struct bnxt_link_info *link_info = &bp->link_info;
10888 |  struct hwrm_port_phy_qcfg_output *resp;
10889 |  struct hwrm_port_phy_qcfg_input *req;
10890 | 	u8 link_state = link_info->link_state;
10891 | 	bool support_changed;
10892 |  int rc;
10893 |
10894 | 	rc = hwrm_req_init(bp, req, HWRM_PORT_PHY_QCFG);
10895 |  if (rc)
10896 |  return rc;
10897 |
10898 | 	resp = hwrm_req_hold(bp, req);
10899 | 	rc = hwrm_req_send(bp, req);
10900 |  if (rc) {
10901 | 		hwrm_req_drop(bp, req);
10902 |  if (BNXT_VF(bp) && rc == -ENODEV) {
10903 | 			netdev_warn(bp->dev, "Cannot obtain link state while PF unavailable.\n");
10904 | 			rc = 0;
10905 | 		}
10906 |  return rc;
10907 | 	}
10908 |
10909 |  memcpy(&link_info->phy_qcfg_resp, resp, sizeof(*resp));
10910 | 	link_info->phy_link_status = resp->link;
10911 | 	link_info->duplex = resp->duplex_cfg;
10912 |  if (bp->hwrm_spec_code >= 0x10800)
10913 | 		link_info->duplex = resp->duplex_state;
10914 | 	link_info->pause = resp->pause;
10915 | 	link_info->auto_mode = resp->auto_mode;
10916 | 	link_info->auto_pause_setting = resp->auto_pause;
10917 | 	link_info->lp_pause = resp->link_partner_adv_pause;
10918 | 	link_info->force_pause_setting = resp->force_pause;
10919 | 	link_info->duplex_setting = resp->duplex_cfg;
10920 |  if (link_info->phy_link_status == BNXT_LINK_LINK) {
10921 | 		link_info->link_speed = le16_to_cpu(resp->link_speed);
10922 |  if (bp->phy_flags & BNXT_PHY_FL_SPEEDS2)
10923 | 			link_info->active_lanes = resp->active_lanes;
10924 | 	} else {
10925 | 		link_info->link_speed = 0;
10926 | 		link_info->active_lanes = 0;
10927 | 	}
10928 | 	link_info->force_link_speed = le16_to_cpu(resp->force_link_speed);
10929 | 	link_info->force_pam4_link_speed =
10930 |  le16_to_cpu(resp->force_pam4_link_speed);
10931 | 	link_info->force_link_speed2 = le16_to_cpu(resp->force_link_speeds2);
10932 | 	link_info->support_speeds = le16_to_cpu(resp->support_speeds);
10933 | 	link_info->support_pam4_speeds = le16_to_cpu(resp->support_pam4_speeds);
10934 | 	link_info->support_speeds2 = le16_to_cpu(resp->support_speeds2);
10935 | 	link_info->auto_link_speeds = le16_to_cpu(resp->auto_link_speed_mask);
10936 | 	link_info->auto_pam4_link_speeds =
10937 |  le16_to_cpu(resp->auto_pam4_link_speed_mask);
10938 | 	link_info->auto_link_speeds2 = le16_to_cpu(resp->auto_link_speeds2);
10939 | 	link_info->lp_auto_link_speeds =
10940 |  le16_to_cpu(resp->link_partner_adv_speeds);
10941 | 	link_info->lp_auto_pam4_link_speeds =
10942 | 		resp->link_partner_pam4_adv_speeds;
10943 | 	link_info->preemphasis = le32_to_cpu(resp->preemphasis);
10944 | 	link_info->phy_ver[0] = resp->phy_maj;
10945 | 	link_info->phy_ver[1] = resp->phy_min;
10946 | 	link_info->phy_ver[2] = resp->phy_bld;
10947 | 	link_info->media_type = resp->media_type;
10948 | 	link_info->phy_type = resp->phy_type;
10949 | 	link_info->transceiver = resp->xcvr_pkg_type;
10950 | 	link_info->phy_addr = resp->eee_config_phy_addr &
10951 |  PORT_PHY_QCFG_RESP_PHY_ADDR_MASK;
10952 | 	link_info->module_status = resp->module_status;
10953 |
10954 |  if (bp->phy_flags & BNXT_PHY_FL_EEE_CAP) {
10955 |  struct ethtool_keee *eee = &bp->eee;
10956 | 		u16 fw_speeds;
10957 |
10958 | 		eee->eee_active = 0;
10959 |  if (resp->eee_config_phy_addr &
10960 |  PORT_PHY_QCFG_RESP_EEE_CONFIG_EEE_ACTIVE) {
10961 | 			eee->eee_active = 1;
10962 | 			fw_speeds = le16_to_cpu(
10963 |  resp->link_partner_adv_eee_link_speed_mask);
10964 | 			_bnxt_fw_to_linkmode(eee->lp_advertised, fw_speeds);
10965 | 		}
10966 |
10967 |  /* Pull initial EEE config */
10968 |  if (!chng_link_state) {
10969 |  if (resp->eee_config_phy_addr &
10970 |  PORT_PHY_QCFG_RESP_EEE_CONFIG_EEE_ENABLED)
10971 | 				eee->eee_enabled = 1;
10972 |
10973 | 			fw_speeds = le16_to_cpu(resp->adv_eee_link_speed_mask);
10974 | 			_bnxt_fw_to_linkmode(eee->advertised, fw_speeds);
10975 |
10976 |  if (resp->eee_config_phy_addr &
10977 |  PORT_PHY_QCFG_RESP_EEE_CONFIG_EEE_TX_LPI) {
10978 | 				__le32 tmr;
10979 |
10980 | 				eee->tx_lpi_enabled = 1;
10981 | 				tmr = resp->xcvr_identifier_type_tx_lpi_timer;
10982 | 				eee->tx_lpi_timer = le32_to_cpu(tmr) &
10983 |  PORT_PHY_QCFG_RESP_TX_LPI_TIMER_MASK;
10984 | 			}
10985 | 		}
10986 | 	}
10987 |
10988 | 	link_info->fec_cfg = PORT_PHY_QCFG_RESP_FEC_CFG_FEC_NONE_SUPPORTED;
10989 |  if (bp->hwrm_spec_code >= 0x10504) {
10990 | 		link_info->fec_cfg = le16_to_cpu(resp->fec_cfg);
10991 | 		link_info->active_fec_sig_mode = resp->active_fec_signal_mode;
10992 | 	}
10993 |  /* TODO: need to add more logic to report VF link */
10994 |  if (chng_link_state) {
10995 |  if (link_info->phy_link_status == BNXT_LINK_LINK)
10996 | 			link_info->link_state = BNXT_LINK_STATE_UP;
10997 |  else
10998 | 			link_info->link_state = BNXT_LINK_STATE_DOWN;
10999 |  if (link_state != link_info->link_state)
11000 | 			bnxt_report_link(bp);
11001 | 	} else {
11002 |  /* always link down if not require to update link state */
11003 | 		link_info->link_state = BNXT_LINK_STATE_DOWN;
11004 | 	}
11005 | 	hwrm_req_drop(bp, req);
11006 |
11007 |  if (!BNXT_PHY_CFG_ABLE(bp))
11008 |  return 0;
11009 |
11010 | 	support_changed = bnxt_support_speed_dropped(link_info);
11011 |  if (support_changed && (link_info->autoneg & BNXT_AUTONEG_SPEED))
11012 | 		bnxt_hwrm_set_link_setting(bp, true, false);
11013 |  return 0;
11014 | }
11015 |
11016 | static void bnxt_get_port_module_status(struct bnxt *bp)
11017 | {
11018 |  struct bnxt_link_info *link_info = &bp->link_info;
11019 |  struct hwrm_port_phy_qcfg_output *resp = &link_info->phy_qcfg_resp;
11020 | 	u8 module_status;
11021 |
11022 |  if (bnxt_update_link(bp, true))
11023 |  return;
11024 |
11025 | 	module_status = link_info->module_status;
11026 |  switch (module_status) {
11027 |  case PORT_PHY_QCFG_RESP_MODULE_STATUS_DISABLETX:
11028 |  case PORT_PHY_QCFG_RESP_MODULE_STATUS_PWRDOWN:
11029 |  case PORT_PHY_QCFG_RESP_MODULE_STATUS_WARNINGMSG:
11030 | 		netdev_warn(bp->dev, "Unqualified SFP+ module detected on port %d\n",
11031 | 			    bp->pf.port_id);
11032 |  if (bp->hwrm_spec_code >= 0x10201) {
11033 | 			netdev_warn(bp->dev, "Module part number %s\n",
11034 | 				    resp->phy_vendor_partnumber);
11035 | 		}
11036 |  if (module_status == PORT_PHY_QCFG_RESP_MODULE_STATUS_DISABLETX)
11037 | 			netdev_warn(bp->dev, "TX is disabled\n");
11038 |  if (module_status == PORT_PHY_QCFG_RESP_MODULE_STATUS_PWRDOWN)
11458 |
11459 | 	req->port_id = cpu_to_le16(bp->pf.port_id);
11460 | 	req->enables = cpu_to_le32(WOL_FILTER_FREE_REQ_ENABLES_WOL_FILTER_ID);
11461 | 	req->wol_filter_id = bp->wol_filter_id;
11462 |
11463 |  return hwrm_req_send(bp, req);
11464 | }
11465 |
11466 | static u16 bnxt_hwrm_get_wol_fltrs(struct bnxt *bp, u16 handle)
11467 | {
11468 |  struct hwrm_wol_filter_qcfg_output *resp;
11469 |  struct hwrm_wol_filter_qcfg_input *req;
11470 | 	u16 next_handle = 0;
11471 |  int rc;
11472 |
11473 | 	rc = hwrm_req_init(bp, req, HWRM_WOL_FILTER_QCFG);
11474 |  if (rc)
11475 |  return rc;
11476 |
11477 | 	req->port_id = cpu_to_le16(bp->pf.port_id);
11478 | 	req->handle = cpu_to_le16(handle);
11479 | 	resp = hwrm_req_hold(bp, req);
11480 | 	rc = hwrm_req_send(bp, req);
11481 |  if (!rc) {
11482 | 		next_handle = le16_to_cpu(resp->next_handle);
11483 |  if (next_handle != 0) {
11484 |  if (resp->wol_type ==
11485 |  WOL_FILTER_ALLOC_REQ_WOL_TYPE_MAGICPKT) {
11486 | 				bp->wol = 1;
11487 | 				bp->wol_filter_id = resp->wol_filter_id;
11488 | 			}
11489 | 		}
11490 | 	}
11491 | 	hwrm_req_drop(bp, req);
11492 |  return next_handle;
11493 | }
11494 |
11495 | static void bnxt_get_wol_settings(struct bnxt *bp)
11496 | {
11497 | 	u16 handle = 0;
11498 |
11499 | 	bp->wol = 0;
11500 |  if (!BNXT_PF(bp) || !(bp->flags & BNXT_FLAG_WOL_CAP))
11501 |  return;
11502 |
11503 |  do {
11504 | 		handle = bnxt_hwrm_get_wol_fltrs(bp, handle);
11505 | 	} while (handle && handle != 0xffff);
11506 | }
11507 |
11508 | static bool bnxt_eee_config_ok(struct bnxt *bp)
11509 | {
11510 |  struct ethtool_keee *eee = &bp->eee;
11511 |  struct bnxt_link_info *link_info = &bp->link_info;
11512 |
11513 |  if (!(bp->phy_flags & BNXT_PHY_FL_EEE_CAP))
    34←Assuming the condition is false→
    35←Taking false branch→
11514 |  return true;
11515 |
11516 |  if (eee->eee_enabled) {
    36←Assuming field 'eee_enabled' is true→
    37←Taking true branch→
11517 |  __ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
11518 |  __ETHTOOL_DECLARE_LINK_MODE_MASK(tmp);
11519 |
11520 | 		_bnxt_fw_to_linkmode(advertising, link_info->advertising);
11521 |
11522 |  if (!(link_info->autoneg & BNXT_AUTONEG_SPEED)) {
    38←Taking false branch→
11523 | 			eee->eee_enabled = 0;
11524 |  return false;
11525 | 		}
11526 |  if (linkmode_andnot(tmp, eee->advertised, advertising)) {
    39←Calling 'linkmode_andnot'→
11527 | 			linkmode_and(eee->advertised, advertising,
11528 | 				     eee->supported);
11529 |  return false;
11530 | 		}
11531 | 	}
11532 |  return true;
11533 | }
11534 |
11535 | static int bnxt_update_phy_setting(struct bnxt *bp)
11536 | {
11537 |  int rc;
11538 | 	bool update_link = false;
11539 | 	bool update_pause = false;
11540 | 	bool update_eee = false;
11541 |  struct bnxt_link_info *link_info = &bp->link_info;
11542 |
11543 | 	rc = bnxt_update_link(bp, true);
11544 |  if (rc21.1'rc' is 021.1'rc' is 021.1'rc' is 0) {
11545 | 		netdev_err(bp->dev, "failed to update link (rc: %x)\n",
11546 | 			   rc);
11547 |  return rc;
11548 | 	}
11549 |  if (!BNXT_SINGLE_PF(bp))
    22←Taking false branch→
11550 |  return 0;
11551 |
11552 |  if ((link_info->autoneg & BNXT_AUTONEG_FLOW_CTRL) &&
    23←Assuming the condition is false→
11553 | 	    (link_info->auto_pause_setting & BNXT_LINK_PAUSE_BOTH) !=
11554 | 	    link_info->req_flow_ctrl)
11555 | 		update_pause = true;
11556 |  if (!(link_info->autoneg & BNXT_AUTONEG_FLOW_CTRL) &&
    25←Taking false branch→
11557 |  link_info->force_pause_setting != link_info->req_flow_ctrl)
    24←Assuming field 'force_pause_setting' is equal to field 'req_flow_ctrl'→
11558 | 		update_pause = true;
11559 |  if (!(link_info->autoneg & BNXT_AUTONEG_SPEED)) {
    26←Assuming the condition is false→
    27←Taking false branch→
11560 |  if (BNXT_AUTO_MODE(link_info->auto_mode))
11561 | 			update_link = true;
11562 |  if (bnxt_force_speed_updated(link_info))
11563 | 			update_link = true;
11564 |  if (link_info->req_duplex != link_info->duplex_setting)
11565 | 			update_link = true;
11566 | 	} else {
11567 |  if (link_info->auto_mode == BNXT_LINK_AUTO_NONE)
    28←Assuming field 'auto_mode' is not equal to BNXT_LINK_AUTO_NONE→
    29←Taking false branch→
11568 | 			update_link = true;
11569 |  if (bnxt_auto_speed_updated(link_info))
    30←Taking false branch→
11570 | 			update_link = true;
11571 | 	}
11572 |
11573 |  /* The last close may have shutdown the link, so need to call
11574 |  * PHY_CFG to bring it back up.
11575 |  */
11576 |  if (!BNXT_LINK_IS_UP(bp))
    31←Assuming field 'link_state' is equal to 2→
    32←Taking false branch→
11577 | 		update_link = true;
11578 |
11579 |  if (!bnxt_eee_config_ok(bp))
    33←Calling 'bnxt_eee_config_ok'→
11580 | 		update_eee = true;
11581 |
11582 |  if (update_link)
11583 | 		rc = bnxt_hwrm_set_link_setting(bp, update_pause, update_eee);
11584 |  else if (update_pause)
11585 | 		rc = bnxt_hwrm_set_pause(bp);
11586 |  if (rc) {
11587 | 		netdev_err(bp->dev, "failed to update phy setting (rc: %x)\n",
11588 | 			   rc);
11589 |  return rc;
11590 | 	}
11591 |
11592 |  return rc;
11593 | }
11594 |
11595 | /* Common routine to pre-map certain register block to different GRC window.
11596 |  * A PF has 16 4K windows and a VF has 4 4K windows. However, only 15 windows
11597 |  * in PF and 3 windows in VF that can be customized to map in different
11598 |  * register blocks.
11599 |  */
11600 | static void bnxt_preset_reg_win(struct bnxt *bp)
11601 | {
11602 |  if (BNXT_PF(bp)) {
11603 |  /* CAG registers map to GRC window #4 */
11604 |  writel(BNXT_CAG_REG_BASE,
11605 | 		       bp->bar0 + BNXT_GRCPF_REG_WINDOW_BASE_OUT + 12);
11606 | 	}
11607 | }
11608 |
11609 | static int bnxt_init_dflt_ring_mode(struct bnxt *bp);
13230 | 			fw_ring_id = cpr2->cp_ring_struct.fw_ring_id;
13231 | 			bnxt_dbg_hwrm_ring_info_get(bp,
13232 |  DBG_RING_INFO_GET_REQ_RING_TYPE_L2_CMPL,
13233 | 				fw_ring_id, &val[0], &val[1]);
13234 | 			cpr->sw_stats.cmn.missed_irqs++;
13235 | 		}
13236 | 	}
13237 | }
13238 |
13239 | static void bnxt_cfg_ntp_filters(struct bnxt *);
13240 |
13241 | static void bnxt_init_ethtool_link_settings(struct bnxt *bp)
13242 | {
13243 |  struct bnxt_link_info *link_info = &bp->link_info;
13244 |
13245 |  if (BNXT_AUTO_MODE(link_info->auto_mode)) {
13246 | 		link_info->autoneg = BNXT_AUTONEG_SPEED;
13247 |  if (bp->hwrm_spec_code >= 0x10201) {
13248 |  if (link_info->auto_pause_setting &
13249 |  PORT_PHY_CFG_REQ_AUTO_PAUSE_AUTONEG_PAUSE)
13250 | 				link_info->autoneg |= BNXT_AUTONEG_FLOW_CTRL;
13251 | 		} else {
13252 | 			link_info->autoneg |= BNXT_AUTONEG_FLOW_CTRL;
13253 | 		}
13254 | 		bnxt_set_auto_speed(link_info);
13255 | 	} else {
13256 | 		bnxt_set_force_speed(link_info);
13257 | 		link_info->req_duplex = link_info->duplex_setting;
13258 | 	}
13259 |  if (link_info->autoneg & BNXT_AUTONEG_FLOW_CTRL)
13260 | 		link_info->req_flow_ctrl =
13261 | 			link_info->auto_pause_setting & BNXT_LINK_PAUSE_BOTH;
13262 |  else
13263 | 		link_info->req_flow_ctrl = link_info->force_pause_setting;
13264 | }
13265 |
13266 | static void bnxt_fw_echo_reply(struct bnxt *bp)
13267 | {
13268 |  struct bnxt_fw_health *fw_health = bp->fw_health;
13269 |  struct hwrm_func_echo_response_input *req;
13270 |  int rc;
13271 |
13272 | 	rc = hwrm_req_init(bp, req, HWRM_FUNC_ECHO_RESPONSE);
13273 |  if (rc)
13274 |  return;
13275 | 	req->event_data1 = cpu_to_le32(fw_health->echo_req_data1);
13276 | 	req->event_data2 = cpu_to_le32(fw_health->echo_req_data2);
13277 | 	hwrm_req_send(bp, req);
13278 | }
13279 |
13280 | static void bnxt_sp_task(struct work_struct *work)
13281 | {
13282 |  struct bnxt *bp = container_of(work, struct bnxt, sp_task);
13283 |
13284 | 	set_bit(BNXT_STATE_IN_SP_TASK, &bp->state);
13285 |  smp_mb__after_atomic();
    1Loop condition is false.  Exiting loop→
    2←Loop condition is false.  Exiting loop→
13286 |  if (!test_bit(BNXT_STATE_OPEN, &bp->state)) {
    3←Loop condition is false.  Exiting loop→
    4←Assuming the condition is true→
    5←Assuming the condition is false→
    6←Taking false branch→
13287 | 		clear_bit(BNXT_STATE_IN_SP_TASK, &bp->state);
13288 |  return;
13289 | 	}
13290 |
13291 |  if (test_and_clear_bit(BNXT_RX_MASK_SP_EVENT, &bp->sp_event))
    7←Assuming the condition is false→
    8←Taking false branch→
13292 | 		bnxt_cfg_rx_mode(bp);
13293 |
13294 |  if (test_and_clear_bit(BNXT_RX_NTP_FLTR_SP_EVENT, &bp->sp_event))
    9←Assuming the condition is false→
    10←Taking false branch→
13295 | 		bnxt_cfg_ntp_filters(bp);
13296 |  if (test_and_clear_bit(BNXT_HWRM_EXEC_FWD_REQ_SP_EVENT, &bp->sp_event))
    11←Assuming the condition is false→
    12←Taking false branch→
13297 | 		bnxt_hwrm_exec_fwd_req(bp);
13298 |  if (test_and_clear_bit(BNXT_HWRM_PF_UNLOAD_SP_EVENT, &bp->sp_event))
    13←Assuming the condition is false→
    14←Taking false branch→
13299 | 		netdev_info(bp->dev, "Receive PF driver unload event!\n");
13300 |  if (test_and_clear_bit(BNXT_PERIODIC_STATS_SP_EVENT, &bp->sp_event)) {
    15←Assuming the condition is false→
    16←Taking false branch→
13301 | 		bnxt_hwrm_port_qstats(bp, 0);
13302 | 		bnxt_hwrm_port_qstats_ext(bp, 0);
13303 | 		bnxt_accumulate_all_stats(bp);
13304 | 	}
13305 |
13306 |  if (test_and_clear_bit(BNXT_LINK_CHNG_SP_EVENT, &bp->sp_event)) {
    17←Assuming the condition is false→
    18←Taking false branch→
13307 |  int rc;
13308 |
13309 |  mutex_lock(&bp->link_lock);
13310 |  if (test_and_clear_bit(BNXT_LINK_SPEED_CHNG_SP_EVENT,
13311 | 				       &bp->sp_event))
13312 | 			bnxt_hwrm_phy_qcaps(bp);
13313 |
13314 | 		rc = bnxt_update_link(bp, true);
13315 |  if (rc)
13316 | 			netdev_err(bp->dev, "SP task can't update link (rc: %x)\n",
13317 | 				   rc);
13318 |
13319 |  if (test_and_clear_bit(BNXT_LINK_CFG_CHANGE_SP_EVENT,
13320 | 				       &bp->sp_event))
13321 | 			bnxt_init_ethtool_link_settings(bp);
13322 | 		mutex_unlock(&bp->link_lock);
13323 | 	}
13324 |  if (test_and_clear_bit(BNXT_UPDATE_PHY_SP_EVENT, &bp->sp_event)) {
    19←Assuming the condition is true→
    20←Taking true branch→
13325 |  int rc;
13326 |
13327 |  mutex_lock(&bp->link_lock);
13328 |  rc = bnxt_update_phy_setting(bp);
    21←Calling 'bnxt_update_phy_setting'→
13329 | 		mutex_unlock(&bp->link_lock);
13330 |  if (rc) {
13331 | 			netdev_warn(bp->dev, "update phy settings retry failed\n");
13332 | 		} else {
13333 | 			bp->link_info.phy_retry = false;
13334 | 			netdev_info(bp->dev, "update phy settings retry succeeded\n");
13335 | 		}
13336 | 	}
13337 |  if (test_and_clear_bit(BNXT_HWRM_PORT_MODULE_SP_EVENT, &bp->sp_event)) {
13338 |  mutex_lock(&bp->link_lock);
13339 | 		bnxt_get_port_module_status(bp);
13340 | 		mutex_unlock(&bp->link_lock);
13341 | 	}
13342 |
13343 |  if (test_and_clear_bit(BNXT_FLOW_STATS_SP_EVENT, &bp->sp_event))
13344 | 		bnxt_tc_flow_stats_work(bp);
13345 |
13346 |  if (test_and_clear_bit(BNXT_RING_COAL_NOW_SP_EVENT, &bp->sp_event))
13347 | 		bnxt_chk_missed_irq(bp);
13348 |
13349 |  if (test_and_clear_bit(BNXT_FW_ECHO_REQUEST_SP_EVENT, &bp->sp_event))
13350 | 		bnxt_fw_echo_reply(bp);
13351 |
13352 |  if (test_and_clear_bit(BNXT_THERMAL_THRESHOLD_SP_EVENT, &bp->sp_event))
13353 | 		bnxt_hwmon_notify_event(bp);
13354 |
13355 |  /* These functions below will clear BNXT_STATE_IN_SP_TASK.  They
13356 |  * must be the last functions to be called before exiting.
13357 |  */
13358 |  if (test_and_clear_bit(BNXT_RESET_TASK_SP_EVENT, &bp->sp_event))
1     | #ifndef __LINKMODE_H
2     | #define __LINKMODE_H
3     |
4     | #include <linux/bitmap.h>
5     | #include <linux/ethtool.h>
6     | #include <uapi/linux/ethtool.h>
7     |
8     | static inline void linkmode_zero(unsigned long *dst)
9     | {
10    | 	bitmap_zero(dst, __ETHTOOL_LINK_MODE_MASK_NBITS);
11    | }
12    |
13    | static inline void linkmode_fill(unsigned long *dst)
14    | {
15    | 	bitmap_fill(dst, __ETHTOOL_LINK_MODE_MASK_NBITS);
16    | }
17    |
18    | static inline void linkmode_copy(unsigned long *dst, const unsigned long *src)
19    | {
20    | 	bitmap_copy(dst, src, __ETHTOOL_LINK_MODE_MASK_NBITS);
21    | }
22    |
23    | static inline void linkmode_and(unsigned long *dst, const unsigned long *a,
24    |  const unsigned long *b)
25    | {
26    | 	bitmap_and(dst, a, b, __ETHTOOL_LINK_MODE_MASK_NBITS);
27    | }
28    |
29    | static inline void linkmode_or(unsigned long *dst, const unsigned long *a,
30    |  const unsigned long *b)
31    | {
32    | 	bitmap_or(dst, a, b, __ETHTOOL_LINK_MODE_MASK_NBITS);
33    | }
34    |
35    | static inline bool linkmode_empty(const unsigned long *src)
36    | {
37    |  return bitmap_empty(src, __ETHTOOL_LINK_MODE_MASK_NBITS);
38    | }
39    |
40    | static inline int linkmode_andnot(unsigned long *dst, const unsigned long *src1,
41    |  const unsigned long *src2)
42    | {
43    |  return bitmap_andnot(dst, src1, src2,  __ETHTOOL_LINK_MODE_MASK_NBITS);
    40←Calling 'bitmap_andnot'→
44    | }
45    |
46    | static inline void linkmode_set_bit(int nr, volatile unsigned long *addr)
47    | {
48    |  __set_bit(nr, addr);
49    | }
50    |
51    | static inline void linkmode_clear_bit(int nr, volatile unsigned long *addr)
52    | {
53    |  __clear_bit(nr, addr);
54    | }
55    |
56    | static inline void linkmode_mod_bit(int nr, volatile unsigned long *addr,
57    |  int set)
58    | {
59    |  if (set)
60    | 		linkmode_set_bit(nr, addr);
61    |  else
62    | 		linkmode_clear_bit(nr, addr);
63    | }
64    |
65    | static inline int linkmode_test_bit(int nr, const volatile unsigned long *addr)
66    | {
67    |  return test_bit(nr, addr);
68    | }
69    |
70    | static inline void linkmode_set_bit_array(const int *array, int array_size,
71    |  unsigned long *addr)
72    | {
73    |  int i;
279   |  unsigned int nbits);
280   | #else
281   | #define bitmap_from_arr32(bitmap, buf, nbits)			\
282   |  bitmap_copy_clear_tail((unsigned long *) (bitmap),	\
283   |  (const unsigned long *) (buf), (nbits))
284   | #define bitmap_to_arr32(buf, bitmap, nbits)			\
285   |  bitmap_copy_clear_tail((unsigned long *) (buf),		\
286   |  (const unsigned long *) (bitmap), (nbits))
287   | #endif
288   |
289   | /*
290   |  * On 64-bit systems bitmaps are represented as u64 arrays internally. So,
291   |  * the conversion is not needed when copying data from/to arrays of u64.
292   |  */
293   | #if BITS_PER_LONG == 32
294   | void bitmap_from_arr64(unsigned long *bitmap, const u64 *buf, unsigned int nbits);
295   | void bitmap_to_arr64(u64 *buf, const unsigned long *bitmap, unsigned int nbits);
296   | #else
297   | #define bitmap_from_arr64(bitmap, buf, nbits)			\
298   |  bitmap_copy_clear_tail((unsigned long *)(bitmap), (const unsigned long *)(buf), (nbits))
299   | #define bitmap_to_arr64(buf, bitmap, nbits)			\
300   |  bitmap_copy_clear_tail((unsigned long *)(buf), (const unsigned long *)(bitmap), (nbits))
301   | #endif
302   |
303   | static inline bool bitmap_and(unsigned long *dst, const unsigned long *src1,
304   |  const unsigned long *src2, unsigned int nbits)
305   | {
306   |  if (small_const_nbits(nbits))
307   |  return (*dst = *src1 & *src2 & BITMAP_LAST_WORD_MASK(nbits)) != 0;
308   |  return __bitmap_and(dst, src1, src2, nbits);
309   | }
310   |
311   | static inline void bitmap_or(unsigned long *dst, const unsigned long *src1,
312   |  const unsigned long *src2, unsigned int nbits)
313   | {
314   |  if (small_const_nbits(nbits))
315   | 		*dst = *src1 | *src2;
316   |  else
317   | 		__bitmap_or(dst, src1, src2, nbits);
318   | }
319   |
320   | static inline void bitmap_xor(unsigned long *dst, const unsigned long *src1,
321   |  const unsigned long *src2, unsigned int nbits)
322   | {
323   |  if (small_const_nbits(nbits))
324   | 		*dst = *src1 ^ *src2;
325   |  else
326   | 		__bitmap_xor(dst, src1, src2, nbits);
327   | }
328   |
329   | static inline bool bitmap_andnot(unsigned long *dst, const unsigned long *src1,
330   |  const unsigned long *src2, unsigned int nbits)
331   | {
332   |  if (small_const_nbits(nbits))
333   |  return (*dst = *src1 & ~(*src2) & BITMAP_LAST_WORD_MASK(nbits)) != 0;
334   |  return __bitmap_andnot(dst, src1, src2, nbits);
    41←Missing hwrm_req_drop() after successful hwrm_req_init()
335   | }
336   |
337   | static inline void bitmap_complement(unsigned long *dst, const unsigned long *src,
338   |  unsigned int nbits)
339   | {
340   |  if (small_const_nbits(nbits))
341   | 		*dst = ~(*src);
342   |  else
343   | 		__bitmap_complement(dst, src, nbits);
344   | }
345   |
346   | #ifdef __LITTLE_ENDIAN
347   | #define BITMAP_MEM_ALIGNMENT 8
348   | #else
349   | #define BITMAP_MEM_ALIGNMENT (8 * sizeof(unsigned long))
350   | #endif
351   | #define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)
352   |
353   | static inline bool bitmap_equal(const unsigned long *src1,
354   |  const unsigned long *src2, unsigned int nbits)
355   | {
356   |  if (small_const_nbits(nbits))
357   |  return !((*src1 ^ *src2) & BITMAP_LAST_WORD_MASK(nbits));
358   |  if (__builtin_constant_p(nbits & BITMAP_MEM_MASK) &&
359   |  IS_ALIGNED(nbits, BITMAP_MEM_ALIGNMENT))
360   |  return !memcmp(src1, src2, nbits / 8);
361   |  return __bitmap_equal(src1, src2, nbits);
362   | }
363   |
364   | /**

Analysis:
- Decision: NotABug
- Reason: The reported location (include/linux/bitmap.h:334) is inside the generic bitmap helper inline function bitmap_andnot(), which contains no calls to hwrm_req_init(), hwrm_req_replace(), or hwrm_req_drop(). Therefore, it cannot exhibit the target bug pattern of leaking an HWRM request by returning without hwrm_req_drop() after a successful hwrm_req_init(). The control flow shown in the annotated trace (bnxt_eee_config_ok -> linkmode_andnot -> bitmap_andnot) is unrelated to HWRM request management. While the surrounding annotated BNXT driver code contains valid hwrm_req_init()/hwrm_req_drop() usage, and there may be other places in the BNXT driver (e.g., bnxt_fw_echo_reply) that warrant review for missing hwrm_req_drop(), the specific report here does not match the target bug pattern and is thus a false positive.

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
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Map: return-symbol of hwrm_req_init() -> req MemRegion*
REGISTER_MAP_WITH_PROGRAMSTATE(PendingInitMap, SymbolRef, const MemRegion *)
// Set: Acquired req MemRegion*s that require hwrm_req_drop() before exit
REGISTER_SET_WITH_PROGRAMSTATE(AcquiredReqs, const MemRegion *)

namespace {

static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreStmt<ReturnStmt>,
    check::EndFunction,
    eval::Assume> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() {
        BT = std::make_unique<BugType>(
            this,
            "Missing hwrm_req_drop() after hwrm_req_init()",
            "Resource management");
      }

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
      ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;

   private:

      void reportLeak(CheckerContext &C, const Stmt *S) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track hwrm_req_init(bp, req, ...)
  if (isCallTo(Call, "hwrm_req_init", C)) {
    // Ensure we have at least 2 args: 0: bp, 1: req
    if (Call.getNumArgs() < 2)
      return;

    const Expr *ReqExpr = Call.getArgExpr(1);
    if (!ReqExpr)
      return;

    const MemRegion *ReqMR = getMemRegionFromExpr(ReqExpr, C);
    if (!ReqMR)
      return;
    ReqMR = ReqMR->getBaseRegion();
    if (!ReqMR)
      return;

    SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
    if (!RetSym)
      return;

    // Record pending init: we'll determine success in evalAssume
    State = State->set<PendingInitMap>(RetSym, ReqMR);
    C.addTransition(State);
    return;
  }

  // Track hwrm_req_drop(bp, req)
  if (isCallTo(Call, "hwrm_req_drop", C)) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *ReqExpr = Call.getArgExpr(1);
    if (!ReqExpr)
      return;

    const MemRegion *ReqMR = getMemRegionFromExpr(ReqExpr, C);
    if (!ReqMR)
      return;
    ReqMR = ReqMR->getBaseRegion();
    if (!ReqMR)
      return;

    // On drop, remove from acquired set (if present)
    auto Set = State->get<AcquiredReqs>();
    if (Set.contains(ReqMR)) {
      State = State->remove<AcquiredReqs>(ReqMR);
      C.addTransition(State);
    }
    return;
  }
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  if (!State)
    return State;

  // Handle pattern: if (rc) or if (!rc) or if (rc == 0) / if (rc != 0)
  if (std::optional<NonLoc> NL = Cond.getAs<NonLoc>()) {
    // Case 1: plain symbolic value 'rc'
    if (SymbolRef Sym = NL->getAsSymbol()) {
      const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym);
      if (PendingReq) {
        // if (rc) with Assumption == false means rc == 0 (success)
        if (!Assumption) {
          State = State->add<AcquiredReqs>(*PendingReq);
        }
        // Consume the pending mapping either way
        State = State->remove<PendingInitMap>(Sym);
      }
      return State;
    }

    // Case 2: symbolic comparison with integer, usually rc == 0 or rc != 0
    if (SymbolRef SE = Cond.getAsSymbol()) {
      if (const auto *SIE = dyn_cast<SymIntExpr>(SE)) {
        BinaryOperator::Opcode Op = SIE->getOpcode();
        SymbolRef Sym = SIE->getLHS();
        const llvm::APSInt &RHS = SIE->getRHS();
        if (Sym) {
          const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym);
          if (PendingReq && RHS == 0) {
            bool SuccessBranch = false;
            if (Op == BO_EQ && Assumption)
              SuccessBranch = true;        // (rc == 0) assumed true
            else if (Op == BO_NE && !Assumption)
              SuccessBranch = true;        // (rc != 0) assumed false

            if (SuccessBranch) {
              State = State->add<AcquiredReqs>(*PendingReq);
            }
            State = State->remove<PendingInitMap>(Sym);
          }
        }
      }
    }
  }

  return State;
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;

  ProgramStateRef State = C.getState();
  // If any acquired req is still live, report a leak.
  if (!State->get<AcquiredReqs>().isEmpty()) {
    reportLeak(C, RS);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!State->get<AcquiredReqs>().isEmpty()) {
    reportLeak(C, nullptr);
  }
}

void SAGenTestChecker::reportLeak(CheckerContext &C, const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing hwrm_req_drop() after successful hwrm_req_init()", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "{{Checker descriptions to be filled}}",
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
