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

File:| /scratch/chenyuan-data/linux-debug/./include/net/page_pool/helpers.h
---|---
Warning:| line 316, column 2
Missing hwrm_req_drop() after successful hwrm_req_init()

### Annotated Source Code


3150  | 		}
3151  |
3152  |  /* The valid test of the entry must be done first before
3153  |  * reading any further.
3154  |  */
3155  |  dma_rmb();
3156  |
3157  | 		type = le16_to_cpu(nqcmp->type);
3158  |  if (NQE_CN_TYPE(type) == NQ_CN_TYPE_CQ_NOTIFICATION) {
3159  | 			u32 idx = le32_to_cpu(nqcmp->cq_handle_low);
3160  | 			u32 cq_type = BNXT_NQ_HDL_TYPE(idx);
3161  |  struct bnxt_cp_ring_info *cpr2;
3162  |
3163  |  /* No more budget for RX work */
3164  |  if (budget && work_done >= budget &&
3165  | 			    cq_type == BNXT_NQ_HDL_TYPE_RX)
3166  |  break;
3167  |
3168  | 			idx = BNXT_NQ_HDL_IDX(idx);
3169  | 			cpr2 = &cpr->cp_ring_arr[idx];
3170  | 			cpr2->had_nqe_notify = 1;
3171  | 			cpr2->toggle = NQE_CN_TOGGLE(type);
3172  | 			work_done += __bnxt_poll_work(bp, cpr2,
3173  | 						      budget - work_done);
3174  | 			cpr->has_more_work |= cpr2->has_more_work;
3175  | 		} else {
3176  | 			bnxt_hwrm_handler(bp, (struct tx_cmp *)nqcmp);
3177  | 		}
3178  | 		raw_cons = NEXT_RAW_CMP(raw_cons);
3179  | 	}
3180  | 	__bnxt_poll_cqs_done(bp, bnapi, DBR_TYPE_CQ, budget);
3181  |  if (raw_cons != cpr->cp_raw_cons) {
3182  | 		cpr->cp_raw_cons = raw_cons;
3183  |  BNXT_DB_NQ_P5(&cpr->cp_db, raw_cons);
3184  | 	}
3185  | poll_done:
3186  | 	cpr_rx = &cpr->cp_ring_arr[0];
3187  |  if (cpr_rx->cp_ring_type == BNXT_NQ_HDL_TYPE_RX &&
3188  | 	    (bp->flags & BNXT_FLAG_DIM)) {
3189  |  struct dim_sample dim_sample = {};
3190  |
3191  | 		dim_update_sample(cpr->event_ctr,
3192  | 				  cpr_rx->rx_packets,
3193  | 				  cpr_rx->rx_bytes,
3194  | 				  &dim_sample);
3195  | 		net_dim(&cpr->dim, dim_sample);
3196  | 	}
3197  |  return work_done;
3198  | }
3199  |
3200  | static void bnxt_free_tx_skbs(struct bnxt *bp)
3201  | {
3202  |  int i, max_idx;
3203  |  struct pci_dev *pdev = bp->pdev;
3204  |
3205  |  if (!bp->tx_ring)
3206  |  return;
3207  |
3208  | 	max_idx = bp->tx_nr_pages * TX_DESC_CNT;
3209  |  for (i = 0; i < bp->tx_nr_rings; i++) {
3210  |  struct bnxt_tx_ring_info *txr = &bp->tx_ring[i];
3211  |  int j;
3212  |
3213  |  if (!txr->tx_buf_ring)
3214  |  continue;
3215  |
3216  |  for (j = 0; j < max_idx;) {
3217  |  struct bnxt_sw_tx_bd *tx_buf = &txr->tx_buf_ring[j];
3218  |  struct sk_buff *skb;
3219  |  int k, last;
3220  |
3221  |  if (i < bp->tx_nr_rings_xdp &&
3222  | 			    tx_buf->action == XDP_REDIRECT) {
3223  |  dma_unmap_single(&pdev->dev,
3224  |  dma_unmap_addr(tx_buf, mapping),
3225  |  dma_unmap_len(tx_buf, len),
3226  |  DMA_TO_DEVICE);
3227  | 				xdp_return_frame(tx_buf->xdpf);
3228  | 				tx_buf->action = 0;
3229  | 				tx_buf->xdpf = NULL;
3230  | 				j++;
3231  |  continue;
3232  | 			}
3233  |
3234  | 			skb = tx_buf->skb;
3235  |  if (!skb) {
3236  | 				j++;
3237  |  continue;
3238  | 			}
3239  |
3240  | 			tx_buf->skb = NULL;
3241  |
3242  |  if (tx_buf->is_push) {
3243  |  dev_kfree_skb(skb);
3244  | 				j += 2;
3245  |  continue;
3246  | 			}
3247  |
3248  |  dma_unmap_single(&pdev->dev,
3249  |  dma_unmap_addr(tx_buf, mapping),
3250  |  skb_headlen(skb),
3251  |  DMA_TO_DEVICE);
3252  |
3253  | 			last = tx_buf->nr_frags;
3254  | 			j += 2;
3255  |  for (k = 0; k < last; k++, j++) {
3256  |  int ring_idx = j & bp->tx_ring_mask;
3257  | 				skb_frag_t *frag = &skb_shinfo(skb)->frags[k];
3258  |
3259  | 				tx_buf = &txr->tx_buf_ring[ring_idx];
3260  |  dma_unmap_page(
3261  |  &pdev->dev,
3262  |  dma_unmap_addr(tx_buf, mapping),
3263  |  skb_frag_size(frag), DMA_TO_DEVICE);
3264  | 			}
3265  |  dev_kfree_skb(skb);
3266  | 		}
3267  | 		netdev_tx_reset_queue(netdev_get_tx_queue(bp->dev, i));
3268  | 	}
3269  | }
3270  |
3271  | static void bnxt_free_one_rx_ring_skbs(struct bnxt *bp, int ring_nr)
3272  | {
3273  |  struct bnxt_rx_ring_info *rxr = &bp->rx_ring[ring_nr];
3274  |  struct pci_dev *pdev = bp->pdev;
3275  |  struct bnxt_tpa_idx_map *map;
3276  |  int i, max_idx, max_agg_idx;
3277  |
3278  | 	max_idx = bp->rx_nr_pages * RX_DESC_CNT;
3279  | 	max_agg_idx = bp->rx_agg_nr_pages * RX_DESC_CNT;
3280  |  if (!rxr->rx_tpa)
    22←Assuming field 'rx_tpa' is null→
    23←Taking true branch→
3281  |  goto skip_rx_tpa_free;
    24←Control jumps to line 3300→
3282  |
3283  |  for (i = 0; i < bp->max_tpa; i++) {
3284  |  struct bnxt_tpa_info *tpa_info = &rxr->rx_tpa[i];
3285  | 		u8 *data = tpa_info->data;
3286  |
3287  |  if (!data)
3288  |  continue;
3289  |
3290  | 		dma_unmap_single_attrs(&pdev->dev, tpa_info->mapping,
3291  | 				       bp->rx_buf_use_size, bp->rx_dir,
3292  |  DMA_ATTR_WEAK_ORDERING);
3293  |
3294  | 		tpa_info->data = NULL;
3295  |
3296  | 		skb_free_frag(data);
3297  | 	}
3298  |
3299  | skip_rx_tpa_free:
3300  |  if (!rxr->rx_buf_ring)
    25←Assuming field 'rx_buf_ring' is non-null→
    26←Taking false branch→
3301  |  goto skip_rx_buf_free;
3302  |
3303  |  for (i = 0; i < max_idx; i++) {
    27←Assuming 'i' is < 'max_idx'→
    28←Loop condition is true.  Entering loop body→
3304  |  struct bnxt_sw_rx_bd *rx_buf = &rxr->rx_buf_ring[i];
3305  | 		dma_addr_t mapping = rx_buf->mapping;
3306  |  void *data = rx_buf->data;
3307  |
3308  |  if (!data)
    29←Assuming 'data' is non-null→
    30←Taking false branch→
3309  |  continue;
3310  |
3311  |  rx_buf->data = NULL;
3312  |  if (BNXT_RX_PAGE_MODE(bp)) {
    31←Assuming the condition is true→
    32←Taking true branch→
3313  |  page_pool_recycle_direct(rxr->page_pool, data);
    33←Calling 'page_pool_recycle_direct'→
3314  | 		} else {
3315  | 			dma_unmap_single_attrs(&pdev->dev, mapping,
3316  | 					       bp->rx_buf_use_size, bp->rx_dir,
3317  |  DMA_ATTR_WEAK_ORDERING);
3318  | 			skb_free_frag(data);
3319  | 		}
3320  | 	}
3321  |
3322  | skip_rx_buf_free:
3323  |  if (!rxr->rx_agg_ring)
3324  |  goto skip_rx_agg_free;
3325  |
3326  |  for (i = 0; i < max_agg_idx; i++) {
3327  |  struct bnxt_sw_rx_agg_bd *rx_agg_buf = &rxr->rx_agg_ring[i];
3328  |  struct page *page = rx_agg_buf->page;
3329  |
3330  |  if (!page)
3331  |  continue;
3332  |
3333  | 		rx_agg_buf->page = NULL;
3334  |  __clear_bit(i, rxr->rx_agg_bmap);
3335  |
3336  | 		page_pool_recycle_direct(rxr->page_pool, page);
3337  | 	}
3338  |
3339  | skip_rx_agg_free:
3340  | 	map = rxr->rx_tpa_idx_map;
3341  |  if (map)
3342  |  memset(map->agg_idx_bmap, 0, sizeof(map->agg_idx_bmap));
3343  | }
3344  |
3345  | static void bnxt_free_rx_skbs(struct bnxt *bp)
3346  | {
3347  |  int i;
3348  |
3349  |  if (!bp->rx_ring)
    17←Assuming field 'rx_ring' is non-null→
    18←Taking false branch→
3350  |  return;
3351  |
3352  |  for (i = 0; i < bp->rx_nr_rings; i++)
    19←Assuming 'i' is < field 'rx_nr_rings'→
    20←Loop condition is true.  Entering loop body→
3353  |  bnxt_free_one_rx_ring_skbs(bp, i);
    21←Calling 'bnxt_free_one_rx_ring_skbs'→
3354  | }
3355  |
3356  | static void bnxt_free_skbs(struct bnxt *bp)
3357  | {
3358  |  bnxt_free_tx_skbs(bp);
3359  |  bnxt_free_rx_skbs(bp);
    16←Calling 'bnxt_free_rx_skbs'→
3360  | }
3361  |
3362  | static void bnxt_init_ctx_mem(struct bnxt_ctx_mem_type *ctxm, void *p, int len)
3363  | {
3364  | 	u8 init_val = ctxm->init_value;
3365  | 	u16 offset = ctxm->init_offset;
3366  | 	u8 *p2 = p;
3367  |  int i;
3368  |
3369  |  if (!init_val)
3370  |  return;
3371  |  if (offset == BNXT_CTX_INIT_INVALID_OFFSET) {
3372  |  memset(p, init_val, len);
3373  |  return;
3374  | 	}
3375  |  for (i = 0; i < len; i += ctxm->entry_size)
3376  | 		*(p2 + i + offset) = init_val;
3377  | }
3378  |
3379  | static void bnxt_free_ring(struct bnxt *bp, struct bnxt_ring_mem_info *rmem)
3380  | {
3381  |  struct pci_dev *pdev = bp->pdev;
3382  |  int i;
3383  |
3384  |  if (!rmem->pg_arr)
3385  |  goto skip_pages;
3386  |
3387  |  for (i = 0; i < rmem->nr_pages; i++) {
3388  |  if (!rmem->pg_arr[i])
3389  |  continue;
5120  |  if (rc)
5121  |  goto alloc_mem_err;
5122  |
5123  | 	rc = bnxt_alloc_cp_rings(bp);
5124  |  if (rc)
5125  |  goto alloc_mem_err;
5126  |
5127  | 	bp->vnic_info[BNXT_VNIC_DEFAULT].flags |= BNXT_VNIC_RSS_FLAG |
5128  |  BNXT_VNIC_MCAST_FLAG |
5129  |  BNXT_VNIC_UCAST_FLAG;
5130  |  if (BNXT_SUPPORTS_NTUPLE_VNIC(bp) && (bp->flags & BNXT_FLAG_RFS))
5131  | 		bp->vnic_info[BNXT_VNIC_NTUPLE].flags |=
5132  |  BNXT_VNIC_RSS_FLAG | BNXT_VNIC_NTUPLE_FLAG;
5133  |
5134  | 	rc = bnxt_alloc_vnic_attributes(bp);
5135  |  if (rc)
5136  |  goto alloc_mem_err;
5137  |  return 0;
5138  |
5139  | alloc_mem_err:
5140  | 	bnxt_free_mem(bp, true);
5141  |  return rc;
5142  | }
5143  |
5144  | static void bnxt_disable_int(struct bnxt *bp)
5145  | {
5146  |  int i;
5147  |
5148  |  if (!bp->bnapi)
5149  |  return;
5150  |
5151  |  for (i = 0; i < bp->cp_nr_rings; i++) {
5152  |  struct bnxt_napi *bnapi = bp->bnapi[i];
5153  |  struct bnxt_cp_ring_info *cpr = &bnapi->cp_ring;
5154  |  struct bnxt_ring_struct *ring = &cpr->cp_ring_struct;
5155  |
5156  |  if (ring->fw_ring_id != INVALID_HW_RING_ID)
5157  | 			bnxt_db_nq(bp, &cpr->cp_db, cpr->cp_raw_cons);
5158  | 	}
5159  | }
5160  |
5161  | static int bnxt_cp_num_to_irq_num(struct bnxt *bp, int n)
5162  | {
5163  |  struct bnxt_napi *bnapi = bp->bnapi[n];
5164  |  struct bnxt_cp_ring_info *cpr;
5165  |
5166  | 	cpr = &bnapi->cp_ring;
5167  |  return cpr->cp_ring_struct.map_idx;
5168  | }
5169  |
5170  | static void bnxt_disable_int_sync(struct bnxt *bp)
5171  | {
5172  |  int i;
5173  |
5174  |  if (!bp->irq_tbl)
5175  |  return;
5176  |
5177  | 	atomic_inc(&bp->intr_sem);
5178  |
5179  | 	bnxt_disable_int(bp);
5180  |  for (i = 0; i < bp->cp_nr_rings; i++) {
5181  |  int map_idx = bnxt_cp_num_to_irq_num(bp, i);
5182  |
5183  | 		synchronize_irq(bp->irq_tbl[map_idx].vector);
5184  | 	}
5185  | }
5186  |
5187  | static void bnxt_enable_int(struct bnxt *bp)
5188  | {
5189  |  int i;
5190  |
5191  | 	atomic_set(&bp->intr_sem, 0);
5192  |  for (i = 0; i < bp->cp_nr_rings; i++) {
5193  |  struct bnxt_napi *bnapi = bp->bnapi[i];
5194  |  struct bnxt_cp_ring_info *cpr = &bnapi->cp_ring;
5195  |
5196  | 		bnxt_db_nq_arm(bp, &cpr->cp_db, cpr->cp_raw_cons);
5197  | 	}
5198  | }
5199  |
5200  | int bnxt_hwrm_func_drv_rgtr(struct bnxt *bp, unsigned long *bmap, int bmap_size,
5201  | 			    bool async_only)
5202  | {
5203  |  DECLARE_BITMAP(async_events_bmap, 256);
5204  | 	u32 *events = (u32 *)async_events_bmap;
5205  |  struct hwrm_func_drv_rgtr_output *resp;
5206  |  struct hwrm_func_drv_rgtr_input *req;
5207  | 	u32 flags;
5208  |  int rc, i;
5209  |
5210  | 	rc = hwrm_req_init(bp, req, HWRM_FUNC_DRV_RGTR);
5261  |
5262  |  if (event_id == ASYNC_EVENT_CMPL_EVENT_ID_ERROR_RECOVERY &&
5263  | 		    !(bp->fw_cap & BNXT_FW_CAP_ERROR_RECOVERY))
5264  |  continue;
5265  |  if (event_id == ASYNC_EVENT_CMPL_EVENT_ID_PHC_UPDATE &&
5266  | 		    !bp->ptp_cfg)
5267  |  continue;
5268  |  __set_bit(bnxt_async_events_arr[i], async_events_bmap);
5269  | 	}
5270  |  if (bmap && bmap_size) {
5271  |  for (i = 0; i < bmap_size; i++) {
5272  |  if (test_bit(i, bmap))
5273  |  __set_bit(i, async_events_bmap);
5274  | 		}
5275  | 	}
5276  |  for (i = 0; i < 8; i++)
5277  | 		req->async_event_fwd[i] |= cpu_to_le32(events[i]);
5278  |
5279  |  if (async_only)
5280  | 		req->enables =
5281  |  cpu_to_le32(FUNC_DRV_RGTR_REQ_ENABLES_ASYNC_EVENT_FWD);
5282  |
5283  | 	resp = hwrm_req_hold(bp, req);
5284  | 	rc = hwrm_req_send(bp, req);
5285  |  if (!rc) {
5286  | 		set_bit(BNXT_STATE_DRV_REGISTERED, &bp->state);
5287  |  if (resp->flags &
5288  |  cpu_to_le32(FUNC_DRV_RGTR_RESP_FLAGS_IF_CHANGE_SUPPORTED))
5289  | 			bp->fw_cap |= BNXT_FW_CAP_IF_CHANGE;
5290  | 	}
5291  | 	hwrm_req_drop(bp, req);
5292  |  return rc;
5293  | }
5294  |
5295  | int bnxt_hwrm_func_drv_unrgtr(struct bnxt *bp)
5296  | {
5297  |  struct hwrm_func_drv_unrgtr_input *req;
5298  |  int rc;
5299  |
5300  |  if (!test_and_clear_bit(BNXT_STATE_DRV_REGISTERED, &bp->state))
5301  |  return 0;
5302  |
5303  | 	rc = hwrm_req_init(bp, req, HWRM_FUNC_DRV_UNRGTR);
5304  |  if (rc)
5305  |  return rc;
5306  |  return hwrm_req_send(bp, req);
5307  | }
5308  |
5309  | static int bnxt_set_tpa(struct bnxt *bp, bool set_tpa);
5310  |
5311  | static int bnxt_hwrm_tunnel_dst_port_free(struct bnxt *bp, u8 tunnel_type)
5312  | {
5313  |  struct hwrm_tunnel_dst_port_free_input *req;
5314  |  int rc;
5315  |
5316  |  if (tunnel_type == TUNNEL_DST_PORT_FREE_REQ_TUNNEL_TYPE_VXLAN &&
5317  | 	    bp->vxlan_fw_dst_port_id == INVALID_HW_RING_ID)
5318  |  return 0;
5319  |  if (tunnel_type == TUNNEL_DST_PORT_FREE_REQ_TUNNEL_TYPE_GENEVE &&
5320  | 	    bp->nge_fw_dst_port_id == INVALID_HW_RING_ID)
5321  |  return 0;
5322  |
5323  | 	rc = hwrm_req_init(bp, req, HWRM_TUNNEL_DST_PORT_FREE);
5324  |  if (rc)
5325  |  return rc;
5326  |
5327  | 	req->tunnel_type = tunnel_type;
5328  |
5329  |  switch (tunnel_type) {
5330  |  case TUNNEL_DST_PORT_FREE_REQ_TUNNEL_TYPE_VXLAN:
5331  | 		req->tunnel_dst_port_id = cpu_to_le16(bp->vxlan_fw_dst_port_id);
5332  | 		bp->vxlan_port = 0;
5333  | 		bp->vxlan_fw_dst_port_id = INVALID_HW_RING_ID;
5334  |  break;
5335  |  case TUNNEL_DST_PORT_FREE_REQ_TUNNEL_TYPE_GENEVE:
5336  | 		req->tunnel_dst_port_id = cpu_to_le16(bp->nge_fw_dst_port_id);
5337  | 		bp->nge_port = 0;
5338  | 		bp->nge_fw_dst_port_id = INVALID_HW_RING_ID;
5339  |  break;
5340  |  case TUNNEL_DST_PORT_FREE_REQ_TUNNEL_TYPE_VXLAN_GPE:
5341  | 		req->tunnel_dst_port_id = cpu_to_le16(bp->vxlan_gpe_fw_dst_port_id);
5342  | 		bp->vxlan_gpe_port = 0;
5343  | 		bp->vxlan_gpe_fw_dst_port_id = INVALID_HW_RING_ID;
5344  |  break;
5345  |  default:
5346  |  break;
5347  | 	}
5348  |
5349  | 	rc = hwrm_req_send(bp, req);
5350  |  if (rc)
5351  | 		netdev_err(bp->dev, "hwrm_tunnel_dst_port_free failed. rc:%d\n",
5352  | 			   rc);
5353  |  if (bp->flags & BNXT_FLAG_TPA)
5354  | 		bnxt_set_tpa(bp, true);
5355  |  return rc;
5356  | }
5357  |
5358  | static int bnxt_hwrm_tunnel_dst_port_alloc(struct bnxt *bp, __be16 port,
5359  | 					   u8 tunnel_type)
5360  | {
5361  |  struct hwrm_tunnel_dst_port_alloc_output *resp;
5362  |  struct hwrm_tunnel_dst_port_alloc_input *req;
5363  |  int rc;
5364  |
5365  | 	rc = hwrm_req_init(bp, req, HWRM_TUNNEL_DST_PORT_ALLOC);
5366  |  if (rc)
5367  |  return rc;
5368  |
5369  | 	req->tunnel_type = tunnel_type;
5370  | 	req->tunnel_dst_port_val = port;
5371  |
5372  | 	resp = hwrm_req_hold(bp, req);
5373  | 	rc = hwrm_req_send(bp, req);
5374  |  if (rc) {
5375  | 		netdev_err(bp->dev, "hwrm_tunnel_dst_port_alloc failed. rc:%d\n",
5376  | 			   rc);
5377  |  goto err_out;
5378  | 	}
5379  |
5380  |  switch (tunnel_type) {
5381  |  case TUNNEL_DST_PORT_ALLOC_REQ_TUNNEL_TYPE_VXLAN:
5382  | 		bp->vxlan_port = port;
5383  | 		bp->vxlan_fw_dst_port_id =
5384  |  le16_to_cpu(resp->tunnel_dst_port_id);
5385  |  break;
6494  |  if (flags & VNIC_QCAPS_RESP_FLAGS_HW_TUNNEL_TPA_CAP)
6495  | 			bp->fw_cap |= BNXT_FW_CAP_VNIC_TUNNEL_TPA;
6496  |  if (flags & VNIC_QCAPS_RESP_FLAGS_RSS_IPSEC_AH_SPI_IPV4_CAP)
6497  | 			bp->rss_cap |= BNXT_RSS_CAP_AH_V4_RSS_CAP;
6498  |  if (flags & VNIC_QCAPS_RESP_FLAGS_RSS_IPSEC_AH_SPI_IPV6_CAP)
6499  | 			bp->rss_cap |= BNXT_RSS_CAP_AH_V6_RSS_CAP;
6500  |  if (flags & VNIC_QCAPS_RESP_FLAGS_RSS_IPSEC_ESP_SPI_IPV4_CAP)
6501  | 			bp->rss_cap |= BNXT_RSS_CAP_ESP_V4_RSS_CAP;
6502  |  if (flags & VNIC_QCAPS_RESP_FLAGS_RSS_IPSEC_ESP_SPI_IPV6_CAP)
6503  | 			bp->rss_cap |= BNXT_RSS_CAP_ESP_V6_RSS_CAP;
6504  | 	}
6505  | 	hwrm_req_drop(bp, req);
6506  |  return rc;
6507  | }
6508  |
6509  | static int bnxt_hwrm_ring_grp_alloc(struct bnxt *bp)
6510  | {
6511  |  struct hwrm_ring_grp_alloc_output *resp;
6512  |  struct hwrm_ring_grp_alloc_input *req;
6513  |  int rc;
6514  | 	u16 i;
6515  |
6516  |  if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
6517  |  return 0;
6518  |
6519  | 	rc = hwrm_req_init(bp, req, HWRM_RING_GRP_ALLOC);
6520  |  if (rc)
6521  |  return rc;
6522  |
6523  | 	resp = hwrm_req_hold(bp, req);
6524  |  for (i = 0; i < bp->rx_nr_rings; i++) {
6525  |  unsigned int grp_idx = bp->rx_ring[i].bnapi->index;
6526  |
6527  | 		req->cr = cpu_to_le16(bp->grp_info[grp_idx].cp_fw_ring_id);
6528  | 		req->rr = cpu_to_le16(bp->grp_info[grp_idx].rx_fw_ring_id);
6529  | 		req->ar = cpu_to_le16(bp->grp_info[grp_idx].agg_fw_ring_id);
6530  | 		req->sc = cpu_to_le16(bp->grp_info[grp_idx].fw_stats_ctx);
6531  |
6532  | 		rc = hwrm_req_send(bp, req);
6533  |
6534  |  if (rc)
6535  |  break;
6536  |
6537  | 		bp->grp_info[grp_idx].fw_grp_id =
6538  |  le32_to_cpu(resp->ring_group_id);
6539  | 	}
6540  | 	hwrm_req_drop(bp, req);
6541  |  return rc;
6542  | }
6543  |
6544  | static void bnxt_hwrm_ring_grp_free(struct bnxt *bp)
6545  | {
6546  |  struct hwrm_ring_grp_free_input *req;
6547  | 	u16 i;
6548  |
6549  |  if (!bp->grp_info || (bp->flags & BNXT_FLAG_CHIP_P5_PLUS))
6550  |  return;
6551  |
6552  |  if (hwrm_req_init(bp, req, HWRM_RING_GRP_FREE))
6553  |  return;
6554  |
6555  | 	hwrm_req_hold(bp, req);
6556  |  for (i = 0; i < bp->cp_nr_rings; i++) {
6557  |  if (bp->grp_info[i].fw_grp_id == INVALID_HW_RING_ID)
6558  |  continue;
6559  | 		req->ring_group_id =
6560  |  cpu_to_le32(bp->grp_info[i].fw_grp_id);
6561  |
6562  | 		hwrm_req_send(bp, req);
6563  | 		bp->grp_info[i].fw_grp_id = INVALID_HW_RING_ID;
6564  | 	}
6565  | 	hwrm_req_drop(bp, req);
6566  | }
6567  |
6568  | static int hwrm_ring_alloc_send_msg(struct bnxt *bp,
6569  |  struct bnxt_ring_struct *ring,
6570  | 				    u32 ring_type, u32 map_index)
6571  | {
6572  |  struct hwrm_ring_alloc_output *resp;
6573  |  struct hwrm_ring_alloc_input *req;
6574  |  struct bnxt_ring_mem_info *rmem = &ring->ring_mem;
6575  |  struct bnxt_ring_grp_info *grp_info;
6576  |  int rc, err = 0;
6577  | 	u16 ring_id;
6578  |
6579  | 	rc = hwrm_req_init(bp, req, HWRM_RING_ALLOC);
6580  |  if (rc)
6581  |  goto exit;
6582  |
6583  | 	req->enables = 0;
6584  |  if (rmem->nr_pages > 1) {
6585  | 		req->page_tbl_addr = cpu_to_le64(rmem->pg_tbl_map);
6586  |  /* Page size is in log2 units */
6587  | 		req->page_size = BNXT_PAGE_SHIFT;
6588  | 		req->page_tbl_depth = 1;
6589  | 	} else {
6590  | 		req->page_tbl_addr =  cpu_to_le64(rmem->dma_arr[0]);
6591  | 	}
6592  | 	req->fbo = 0;
6593  |  /* Association of ring index with doorbell index and MSIX number */
6594  | 	req->logical_id = cpu_to_le16(map_index);
6595  |
6887  | 			u32 map_idx = grp_idx + bp->rx_nr_rings;
6888  |
6889  | 			rc = hwrm_ring_alloc_send_msg(bp, ring, type, map_idx);
6890  |  if (rc)
6891  |  goto err_out;
6892  |
6893  | 			bnxt_set_db(bp, &rxr->rx_agg_db, type, map_idx,
6894  | 				    ring->fw_ring_id);
6895  | 			bnxt_db_write(bp, &rxr->rx_agg_db, rxr->rx_agg_prod);
6896  | 			bnxt_db_write(bp, &rxr->rx_db, rxr->rx_prod);
6897  | 			bp->grp_info[grp_idx].agg_fw_ring_id = ring->fw_ring_id;
6898  | 		}
6899  | 	}
6900  | err_out:
6901  |  return rc;
6902  | }
6903  |
6904  | static int hwrm_ring_free_send_msg(struct bnxt *bp,
6905  |  struct bnxt_ring_struct *ring,
6906  | 				   u32 ring_type, int cmpl_ring_id)
6907  | {
6908  |  struct hwrm_ring_free_output *resp;
6909  |  struct hwrm_ring_free_input *req;
6910  | 	u16 error_code = 0;
6911  |  int rc;
6912  |
6913  |  if (BNXT_NO_FW_ACCESS(bp))
6914  |  return 0;
6915  |
6916  | 	rc = hwrm_req_init(bp, req, HWRM_RING_FREE);
6917  |  if (rc)
6918  |  goto exit;
6919  |
6920  | 	req->cmpl_ring = cpu_to_le16(cmpl_ring_id);
6921  | 	req->ring_type = ring_type;
6922  | 	req->ring_id = cpu_to_le16(ring->fw_ring_id);
6923  |
6924  | 	resp = hwrm_req_hold(bp, req);
6925  | 	rc = hwrm_req_send(bp, req);
6926  | 	error_code = le16_to_cpu(resp->error_code);
6927  | 	hwrm_req_drop(bp, req);
6928  | exit:
6929  |  if (rc || error_code) {
6930  | 		netdev_err(bp->dev, "hwrm_ring_free type %d failed. rc:%x err:%x\n",
6931  | 			   ring_type, rc, error_code);
6932  |  return -EIO;
6933  | 	}
6934  |  return 0;
6935  | }
6936  |
6937  | static void bnxt_hwrm_ring_free(struct bnxt *bp, bool close_path)
6938  | {
6939  | 	u32 type;
6940  |  int i;
6941  |
6942  |  if (!bp->bnapi)
6943  |  return;
6944  |
6945  |  for (i = 0; i < bp->tx_nr_rings; i++) {
6946  |  struct bnxt_tx_ring_info *txr = &bp->tx_ring[i];
6947  |  struct bnxt_ring_struct *ring = &txr->tx_ring_struct;
6948  |
6949  |  if (ring->fw_ring_id != INVALID_HW_RING_ID) {
6950  | 			u32 cmpl_ring_id = bnxt_cp_ring_for_tx(bp, txr);
6951  |
6952  | 			hwrm_ring_free_send_msg(bp, ring,
6953  |  RING_FREE_REQ_RING_TYPE_TX,
6954  | 						close_path ? cmpl_ring_id :
6955  |  INVALID_HW_RING_ID);
6956  | 			ring->fw_ring_id = INVALID_HW_RING_ID;
6957  | 		}
6958  | 	}
6959  |
6960  |  for (i = 0; i < bp->rx_nr_rings; i++) {
6961  |  struct bnxt_rx_ring_info *rxr = &bp->rx_ring[i];
6962  |  struct bnxt_ring_struct *ring = &rxr->rx_ring_struct;
6963  | 		u32 grp_idx = rxr->bnapi->index;
6964  |
6965  |  if (ring->fw_ring_id != INVALID_HW_RING_ID) {
6966  | 			u32 cmpl_ring_id = bnxt_cp_ring_for_rx(bp, rxr);
6967  |
6968  | 			hwrm_ring_free_send_msg(bp, ring,
6969  |  RING_FREE_REQ_RING_TYPE_RX,
6970  | 						close_path ? cmpl_ring_id :
6971  |  INVALID_HW_RING_ID);
6972  | 			ring->fw_ring_id = INVALID_HW_RING_ID;
6973  | 			bp->grp_info[grp_idx].rx_fw_ring_id =
6974  |  INVALID_HW_RING_ID;
6975  | 		}
6976  | 	}
6977  |
6978  |  if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
6979  | 		type = RING_FREE_REQ_RING_TYPE_RX_AGG;
6980  |  else
6981  | 		type = RING_FREE_REQ_RING_TYPE_RX;
6982  |  for (i = 0; i < bp->rx_nr_rings; i++) {
6983  |  struct bnxt_rx_ring_info *rxr = &bp->rx_ring[i];
6984  |  struct bnxt_ring_struct *ring = &rxr->rx_agg_ring_struct;
6985  | 		u32 grp_idx = rxr->bnapi->index;
6986  |
6987  |  if (ring->fw_ring_id != INVALID_HW_RING_ID) {
6988  | 			u32 cmpl_ring_id = bnxt_cp_ring_for_rx(bp, rxr);
6989  |
6990  | 			hwrm_ring_free_send_msg(bp, ring, type,
6991  | 						close_path ? cmpl_ring_id :
6992  |  INVALID_HW_RING_ID);
6993  | 			ring->fw_ring_id = INVALID_HW_RING_ID;
6994  | 			bp->grp_info[grp_idx].agg_fw_ring_id =
6995  |  INVALID_HW_RING_ID;
6996  | 		}
6997  | 	}
6998  |
6999  |  /* The completion rings are about to be freed.  After that the
7000  |  * IRQ doorbell will not work anymore.  So we need to disable
7001  |  * IRQ here.
7002  |  */
7003  | 	bnxt_disable_int_sync(bp);
7004  |
7005  |  if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
7006  | 		type = RING_FREE_REQ_RING_TYPE_NQ;
7007  |  else
7008  | 		type = RING_FREE_REQ_RING_TYPE_L2_CMPL;
7009  |  for (i = 0; i < bp->cp_nr_rings; i++) {
7010  |  struct bnxt_napi *bnapi = bp->bnapi[i];
7011  |  struct bnxt_cp_ring_info *cpr = &bnapi->cp_ring;
7012  |  struct bnxt_ring_struct *ring;
7013  |  int j;
7014  |
7015  |  for (j = 0; j < cpr->cp_ring_count && cpr->cp_ring_arr; j++) {
7016  |  struct bnxt_cp_ring_info *cpr2 = &cpr->cp_ring_arr[j];
7017  |
7018  | 			ring = &cpr2->cp_ring_struct;
7019  |  if (ring->fw_ring_id == INVALID_HW_RING_ID)
7020  |  continue;
7021  | 			hwrm_ring_free_send_msg(bp, ring,
7022  |  RING_FREE_REQ_RING_TYPE_L2_CMPL,
7023  |  INVALID_HW_RING_ID);
7024  | 			ring->fw_ring_id = INVALID_HW_RING_ID;
7025  | 		}
7026  | 		ring = &cpr->cp_ring_struct;
7027  |  if (ring->fw_ring_id != INVALID_HW_RING_ID) {
7028  | 			hwrm_ring_free_send_msg(bp, ring, type,
7029  |  INVALID_HW_RING_ID);
7030  | 			ring->fw_ring_id = INVALID_HW_RING_ID;
7031  | 			bp->grp_info[i].cp_fw_ring_id = INVALID_HW_RING_ID;
7032  | 		}
7033  | 	}
7034  | }
7035  |
7036  | static int __bnxt_trim_rings(struct bnxt *bp, int *rx, int *tx, int max,
7037  | 			     bool shared);
7038  | static int bnxt_trim_rings(struct bnxt *bp, int *rx, int *tx, int max,
7039  | 			   bool shared);
7751  | int bnxt_hwrm_set_coal(struct bnxt *bp)
7752  | {
7753  |  struct hwrm_ring_cmpl_ring_cfg_aggint_params_input *req_rx, *req_tx;
7754  |  int i, rc;
7755  |
7756  | 	rc = hwrm_req_init(bp, req_rx, HWRM_RING_CMPL_RING_CFG_AGGINT_PARAMS);
7757  |  if (rc)
7758  |  return rc;
7759  |
7760  | 	rc = hwrm_req_init(bp, req_tx, HWRM_RING_CMPL_RING_CFG_AGGINT_PARAMS);
7761  |  if (rc) {
7762  | 		hwrm_req_drop(bp, req_rx);
7763  |  return rc;
7764  | 	}
7765  |
7766  | 	bnxt_hwrm_set_coal_params(bp, &bp->rx_coal, req_rx);
7767  | 	bnxt_hwrm_set_coal_params(bp, &bp->tx_coal, req_tx);
7768  |
7769  | 	hwrm_req_hold(bp, req_rx);
7770  | 	hwrm_req_hold(bp, req_tx);
7771  |  for (i = 0; i < bp->cp_nr_rings; i++) {
7772  |  struct bnxt_napi *bnapi = bp->bnapi[i];
7773  |  struct bnxt_coal *hw_coal;
7774  |
7775  |  if (!bnapi->rx_ring)
7776  | 			rc = bnxt_hwrm_set_tx_coal(bp, bnapi, req_tx);
7777  |  else
7778  | 			rc = bnxt_hwrm_set_rx_coal(bp, bnapi, req_rx);
7779  |  if (rc)
7780  |  break;
7781  |
7782  |  if (!(bp->flags & BNXT_FLAG_CHIP_P5_PLUS))
7783  |  continue;
7784  |
7785  |  if (bnapi->rx_ring && bnapi->tx_ring[0]) {
7786  | 			rc = bnxt_hwrm_set_tx_coal(bp, bnapi, req_tx);
7787  |  if (rc)
7788  |  break;
7789  | 		}
7790  |  if (bnapi->rx_ring)
7791  | 			hw_coal = &bp->rx_coal;
7792  |  else
7793  | 			hw_coal = &bp->tx_coal;
7794  | 		__bnxt_hwrm_set_coal_nq(bp, bnapi, hw_coal);
7795  | 	}
7796  | 	hwrm_req_drop(bp, req_rx);
7797  | 	hwrm_req_drop(bp, req_tx);
7798  |  return rc;
7799  | }
7800  |
7801  | static void bnxt_hwrm_stat_ctx_free(struct bnxt *bp)
7802  | {
7803  |  struct hwrm_stat_ctx_clr_stats_input *req0 = NULL;
7804  |  struct hwrm_stat_ctx_free_input *req;
7805  |  int i;
7806  |
7807  |  if (!bp->bnapi)
7808  |  return;
7809  |
7810  |  if (BNXT_CHIP_TYPE_NITRO_A0(bp))
7811  |  return;
7812  |
7813  |  if (hwrm_req_init(bp, req, HWRM_STAT_CTX_FREE))
7814  |  return;
7815  |  if (BNXT_FW_MAJ(bp) <= 20) {
7816  |  if (hwrm_req_init(bp, req0, HWRM_STAT_CTX_CLR_STATS)) {
7817  | 			hwrm_req_drop(bp, req);
7818  |  return;
7819  | 		}
7820  | 		hwrm_req_hold(bp, req0);
7821  | 	}
7822  | 	hwrm_req_hold(bp, req);
7823  |  for (i = 0; i < bp->cp_nr_rings; i++) {
7824  |  struct bnxt_napi *bnapi = bp->bnapi[i];
7825  |  struct bnxt_cp_ring_info *cpr = &bnapi->cp_ring;
7826  |
7827  |  if (cpr->hw_stats_ctx_id != INVALID_STATS_CTX_ID) {
7828  | 			req->stat_ctx_id = cpu_to_le32(cpr->hw_stats_ctx_id);
7829  |  if (req0) {
7830  | 				req0->stat_ctx_id = req->stat_ctx_id;
7831  | 				hwrm_req_send(bp, req0);
7832  | 			}
7833  | 			hwrm_req_send(bp, req);
7834  |
7835  | 			cpr->hw_stats_ctx_id = INVALID_STATS_CTX_ID;
7836  | 		}
7837  | 	}
7838  | 	hwrm_req_drop(bp, req);
7839  |  if (req0)
7840  | 		hwrm_req_drop(bp, req0);
7841  | }
7842  |
7843  | static int bnxt_hwrm_stat_ctx_alloc(struct bnxt *bp)
7844  | {
7845  |  struct hwrm_stat_ctx_alloc_output *resp;
7846  |  struct hwrm_stat_ctx_alloc_input *req;
7847  |  int rc, i;
7848  |
7849  |  if (BNXT_CHIP_TYPE_NITRO_A0(bp))
7850  |  return 0;
7851  |
7852  | 	rc = hwrm_req_init(bp, req, HWRM_STAT_CTX_ALLOC);
7853  |  if (rc)
7854  |  return rc;
7855  |
7856  | 	req->stats_dma_length = cpu_to_le16(bp->hw_ring_stats_size);
7857  | 	req->update_period_ms = cpu_to_le32(bp->stats_coal_ticks / 1000);
7858  |
7859  | 	resp = hwrm_req_hold(bp, req);
7860  |  for (i = 0; i < bp->cp_nr_rings; i++) {
7861  |  struct bnxt_napi *bnapi = bp->bnapi[i];
7862  |  struct bnxt_cp_ring_info *cpr = &bnapi->cp_ring;
7863  |
7864  | 		req->stats_dma_addr = cpu_to_le64(cpr->stats.hw_stats_map);
7865  |
7866  | 		rc = hwrm_req_send(bp, req);
7867  |  if (rc)
7868  |  break;
7869  |
9603  | 		bp->fw_rx_stats_ext_size = 0;
9604  | 		bp->fw_tx_stats_ext_size = 0;
9605  | 	}
9606  | 	hwrm_req_drop(bp, req_qs);
9607  |
9608  |  if (flags)
9609  |  return rc;
9610  |
9611  |  if (bp->fw_tx_stats_ext_size <=
9612  |  offsetof(struct tx_port_stats_ext, pfc_pri0_tx_duration_us) / 8) {
9613  | 		bp->pri2cos_valid = 0;
9614  |  return rc;
9615  | 	}
9616  |
9617  | 	rc = hwrm_req_init(bp, req_qc, HWRM_QUEUE_PRI2COS_QCFG);
9618  |  if (rc)
9619  |  return rc;
9620  |
9621  | 	req_qc->flags = cpu_to_le32(QUEUE_PRI2COS_QCFG_REQ_FLAGS_IVLAN);
9622  |
9623  | 	resp_qc = hwrm_req_hold(bp, req_qc);
9624  | 	rc = hwrm_req_send(bp, req_qc);
9625  |  if (!rc) {
9626  | 		u8 *pri2cos;
9627  |  int i, j;
9628  |
9629  | 		pri2cos = &resp_qc->pri0_cos_queue_id;
9630  |  for (i = 0; i < 8; i++) {
9631  | 			u8 queue_id = pri2cos[i];
9632  | 			u8 queue_idx;
9633  |
9634  |  /* Per port queue IDs start from 0, 10, 20, etc */
9635  | 			queue_idx = queue_id % 10;
9636  |  if (queue_idx > BNXT_MAX_QUEUE) {
9637  | 				bp->pri2cos_valid = false;
9638  | 				hwrm_req_drop(bp, req_qc);
9639  |  return rc;
9640  | 			}
9641  |  for (j = 0; j < bp->max_q; j++) {
9642  |  if (bp->q_ids[j] == queue_id)
9643  | 					bp->pri2cos_idx[i] = queue_idx;
9644  | 			}
9645  | 		}
9646  | 		bp->pri2cos_valid = true;
9647  | 	}
9648  | 	hwrm_req_drop(bp, req_qc);
9649  |
9650  |  return rc;
9651  | }
9652  |
9653  | static void bnxt_hwrm_free_tunnel_ports(struct bnxt *bp)
9654  | {
9655  | 	bnxt_hwrm_tunnel_dst_port_free(bp,
9656  |  TUNNEL_DST_PORT_FREE_REQ_TUNNEL_TYPE_VXLAN);
9657  | 	bnxt_hwrm_tunnel_dst_port_free(bp,
9658  |  TUNNEL_DST_PORT_FREE_REQ_TUNNEL_TYPE_GENEVE);
9659  | }
9660  |
9661  | static int bnxt_set_tpa(struct bnxt *bp, bool set_tpa)
9662  | {
9663  |  int rc, i;
9664  | 	u32 tpa_flags = 0;
9665  |
9666  |  if (set_tpa)
9667  | 		tpa_flags = bp->flags & BNXT_FLAG_TPA;
9668  |  else if (BNXT_NO_FW_ACCESS(bp))
9669  |  return 0;
9670  |  for (i = 0; i < bp->nr_vnics; i++) {
9671  | 		rc = bnxt_hwrm_vnic_set_tpa(bp, i, tpa_flags);
9672  |  if (rc) {
9673  | 			netdev_err(bp->dev, "hwrm vnic set tpa failure rc for vnic %d: %x\n",
9674  | 				   i, rc);
9675  |  return rc;
9676  | 		}
9677  | 	}
9678  |  return 0;
9679  | }
9680  |
9681  | static void bnxt_hwrm_clear_vnic_rss(struct bnxt *bp)
9682  | {
9683  |  int i;
9684  |
9685  |  for (i = 0; i < bp->nr_vnics; i++)
9686  | 		bnxt_hwrm_vnic_set_rss(bp, i, false);
9687  | }
9688  |
9689  | static void bnxt_clear_vnic(struct bnxt *bp)
9690  | {
9691  |  if (!bp->vnic_info)
9692  |  return;
9693  |
9694  | 	bnxt_hwrm_clear_vnic_filter(bp);
9695  |  if (!(bp->flags & BNXT_FLAG_CHIP_P5_PLUS)) {
9696  |  /* clear all RSS setting before free vnic ctx */
9697  | 		bnxt_hwrm_clear_vnic_rss(bp);
9698  | 		bnxt_hwrm_vnic_ctx_free(bp);
9699  | 	}
9700  |  /* before free the vnic, undo the vnic tpa settings */
9701  |  if (bp->flags & BNXT_FLAG_TPA)
9702  | 		bnxt_set_tpa(bp, false);
9703  | 	bnxt_hwrm_vnic_free(bp);
9704  |  if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
9705  | 		bnxt_hwrm_vnic_ctx_free(bp);
9706  | }
9707  |
9708  | static void bnxt_hwrm_resource_free(struct bnxt *bp, bool close_path,
9709  | 				    bool irq_re_init)
9710  | {
9711  | 	bnxt_clear_vnic(bp);
9712  | 	bnxt_hwrm_ring_free(bp, close_path);
9713  | 	bnxt_hwrm_ring_grp_free(bp);
9714  |  if (irq_re_init) {
9715  | 		bnxt_hwrm_stat_ctx_free(bp);
9716  | 		bnxt_hwrm_free_tunnel_ports(bp);
9717  | 	}
9718  | }
9719  |
9720  | static int bnxt_hwrm_set_br_mode(struct bnxt *bp, u16 br_mode)
9721  | {
9722  |  struct hwrm_func_cfg_input *req;
9723  | 	u8 evb_mode;
9724  |  int rc;
9725  |
9726  |  if (br_mode == BRIDGE_MODE_VEB)
9727  | 		evb_mode = FUNC_CFG_REQ_EVB_MODE_VEB;
9728  |  else if (br_mode == BRIDGE_MODE_VEPA)
9729  | 		evb_mode = FUNC_CFG_REQ_EVB_MODE_VEPA;
9730  |  else
9731  |  return -EINVAL;
9732  |
9733  | 	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &req);
9734  |  if (rc)
9735  |  return rc;
9736  |
9737  | 	req->fid = cpu_to_le16(0xffff);
9738  | 	req->enables = cpu_to_le32(FUNC_CFG_REQ_ENABLES_EVB_MODE);
9739  | 	req->evb_mode = evb_mode;
9740  |  return hwrm_req_send(bp, req);
9741  | }
9742  |
9743  | static int bnxt_hwrm_set_cache_line_size(struct bnxt *bp, int size)
9744  | {
9745  |  struct hwrm_func_cfg_input *req;
9746  |  int rc;
10015 | 	vnic->rx_mask = 0;
10016 |  if (test_bit(BNXT_STATE_HALF_OPEN, &bp->state))
10017 |  goto skip_rx_mask;
10018 |
10019 |  if (bp->dev->flags & IFF_BROADCAST)
10020 | 		vnic->rx_mask |= CFA_L2_SET_RX_MASK_REQ_MASK_BCAST;
10021 |
10022 |  if (bp->dev->flags & IFF_PROMISC)
10023 | 		vnic->rx_mask |= CFA_L2_SET_RX_MASK_REQ_MASK_PROMISCUOUS;
10024 |
10025 |  if (bp->dev->flags & IFF_ALLMULTI) {
10026 | 		vnic->rx_mask |= CFA_L2_SET_RX_MASK_REQ_MASK_ALL_MCAST;
10027 | 		vnic->mc_list_count = 0;
10028 | 	} else if (bp->dev->flags & IFF_MULTICAST) {
10029 | 		u32 mask = 0;
10030 |
10031 | 		bnxt_mc_list_updated(bp, &mask);
10032 | 		vnic->rx_mask |= mask;
10033 | 	}
10034 |
10035 | 	rc = bnxt_cfg_rx_mode(bp);
10036 |  if (rc)
10037 |  goto err_out;
10038 |
10039 | skip_rx_mask:
10040 | 	rc = bnxt_hwrm_set_coal(bp);
10041 |  if (rc)
10042 | 		netdev_warn(bp->dev, "HWRM set coalescing failure rc: %x\n",
10043 | 				rc);
10044 |
10045 |  if (BNXT_CHIP_TYPE_NITRO_A0(bp)) {
10046 | 		rc = bnxt_setup_nitroa0_vnic(bp);
10047 |  if (rc)
10048 | 			netdev_err(bp->dev, "Special vnic setup failure for NS2 A0 rc: %x\n",
10049 | 				   rc);
10050 | 	}
10051 |
10052 |  if (BNXT_VF(bp)) {
10053 | 		bnxt_hwrm_func_qcfg(bp);
10054 | 		netdev_update_features(bp->dev);
10055 | 	}
10056 |
10057 |  return 0;
10058 |
10059 | err_out:
10060 | 	bnxt_hwrm_resource_free(bp, 0, true);
10061 |
10062 |  return rc;
10063 | }
10064 |
10065 | static int bnxt_shutdown_nic(struct bnxt *bp, bool irq_re_init)
10066 | {
10067 | 	bnxt_hwrm_resource_free(bp, 1, irq_re_init);
10068 |  return 0;
10069 | }
10070 |
10071 | static int bnxt_init_nic(struct bnxt *bp, bool irq_re_init)
10072 | {
10073 | 	bnxt_init_cp_rings(bp);
10074 | 	bnxt_init_rx_rings(bp);
10075 | 	bnxt_init_tx_rings(bp);
10076 | 	bnxt_init_ring_grps(bp, irq_re_init);
10077 | 	bnxt_init_vnics(bp);
10078 |
10079 |  return bnxt_init_chip(bp, irq_re_init);
10080 | }
10081 |
10082 | static int bnxt_set_real_num_queues(struct bnxt *bp)
10083 | {
10084 |  int rc;
10085 |  struct net_device *dev = bp->dev;
10086 |
10087 | 	rc = netif_set_real_num_tx_queues(dev, bp->tx_nr_rings -
10088 | 					  bp->tx_nr_rings_xdp);
10089 |  if (rc)
10090 |  return rc;
10091 |
10092 | 	rc = netif_set_real_num_rx_queues(dev, bp->rx_nr_rings);
10093 |  if (rc)
10094 |  return rc;
10095 |
10096 | #ifdef CONFIG_RFS_ACCEL
10097 |  if (bp->flags & BNXT_FLAG_RFS)
10098 | 		dev->rx_cpu_rmap = alloc_irq_cpu_rmap(bp->rx_nr_rings);
10561 | {
10562 |  int i;
10563 |
10564 |  if (!bp->bnapi)
10565 |  return;
10566 |
10567 |  for (i = 0; i < bp->rx_nr_rings; i++)
10568 | 		netif_queue_set_napi(bp->dev, i, NETDEV_QUEUE_TYPE_RX, NULL);
10569 |  for (i = 0; i < bp->tx_nr_rings - bp->tx_nr_rings_xdp; i++)
10570 | 		netif_queue_set_napi(bp->dev, i, NETDEV_QUEUE_TYPE_TX, NULL);
10571 |
10572 |  for (i = 0; i < bp->cp_nr_rings; i++) {
10573 |  struct bnxt_napi *bnapi = bp->bnapi[i];
10574 |
10575 | 		__netif_napi_del(&bnapi->napi);
10576 | 	}
10577 |  /* We called __netif_napi_del(), we need
10578 |  * to respect an RCU grace period before freeing napi structures.
10579 |  */
10580 | 	synchronize_net();
10581 | }
10582 |
10583 | static void bnxt_init_napi(struct bnxt *bp)
10584 | {
10585 |  int i;
10586 |  unsigned int cp_nr_rings = bp->cp_nr_rings;
10587 |  struct bnxt_napi *bnapi;
10588 |
10589 |  if (bp->flags & BNXT_FLAG_USING_MSIX) {
10590 |  int (*poll_fn)(struct napi_struct *, int) = bnxt_poll;
10591 |
10592 |  if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
10593 | 			poll_fn = bnxt_poll_p5;
10594 |  else if (BNXT_CHIP_TYPE_NITRO_A0(bp))
10595 | 			cp_nr_rings--;
10596 |  for (i = 0; i < cp_nr_rings; i++) {
10597 | 			bnapi = bp->bnapi[i];
10598 | 			netif_napi_add(bp->dev, &bnapi->napi, poll_fn);
10599 | 		}
10600 |  if (BNXT_CHIP_TYPE_NITRO_A0(bp)) {
10601 | 			bnapi = bp->bnapi[cp_nr_rings];
10602 | 			netif_napi_add(bp->dev, &bnapi->napi,
10603 | 				       bnxt_poll_nitroa0);
10604 | 		}
10605 | 	} else {
10606 | 		bnapi = bp->bnapi[0];
10607 | 		netif_napi_add(bp->dev, &bnapi->napi, bnxt_poll);
10608 | 	}
10609 | }
10610 |
10611 | static void bnxt_disable_napi(struct bnxt *bp)
10612 | {
10613 |  int i;
10614 |
10615 |  if (!bp->bnapi ||
10616 | 	    test_and_set_bit(BNXT_STATE_NAPI_DISABLED, &bp->state))
10617 |  return;
10618 |
10619 |  for (i = 0; i < bp->cp_nr_rings; i++) {
10620 |  struct bnxt_napi *bnapi = bp->bnapi[i];
10621 |  struct bnxt_cp_ring_info *cpr;
10622 |
10623 | 		cpr = &bnapi->cp_ring;
10624 |  if (bnapi->tx_fault)
10625 | 			cpr->sw_stats.tx.tx_resets++;
10626 |  if (bnapi->in_reset)
10627 | 			cpr->sw_stats.rx.rx_resets++;
10628 | 		napi_disable(&bnapi->napi);
10629 |  if (bnapi->rx_ring)
10630 | 			cancel_work_sync(&cpr->dim.work);
10631 | 	}
10632 | }
10633 |
10634 | static void bnxt_enable_napi(struct bnxt *bp)
10635 | {
10636 |  int i;
10637 |
10638 | 	clear_bit(BNXT_STATE_NAPI_DISABLED, &bp->state);
10639 |  for (i = 0; i < bp->cp_nr_rings; i++) {
10640 |  struct bnxt_napi *bnapi = bp->bnapi[i];
10641 |  struct bnxt_cp_ring_info *cpr;
10642 |
10643 | 		bnapi->tx_fault = 0;
10644 |
10645 | 		cpr = &bnapi->cp_ring;
10646 | 		bnapi->in_reset = false;
10647 |
10648 |  if (bnapi->rx_ring) {
10649 |  INIT_WORK(&cpr->dim.work, bnxt_dim_work);
10650 | 			cpr->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
10651 | 		}
10652 | 		napi_enable(&bnapi->napi);
10653 | 	}
10654 | }
10655 |
10656 | void bnxt_tx_disable(struct bnxt *bp)
10657 | {
10658 |  int i;
10659 |  struct bnxt_tx_ring_info *txr;
10660 |
10661 |  if (bp->tx_ring) {
10662 |  for (i = 0; i < bp->tx_nr_rings; i++) {
10663 | 			txr = &bp->tx_ring[i];
10664 |  WRITE_ONCE(txr->dev_state, BNXT_DEV_STATE_CLOSING);
10665 | 		}
10666 | 	}
10667 |  /* Make sure napi polls see @dev_state change */
10668 | 	synchronize_net();
10669 |  /* Drop carrier first to prevent TX timeout */
10670 | 	netif_carrier_off(bp->dev);
10671 |  /* Stop all TX queues */
10672 | 	netif_tx_disable(bp->dev);
10673 | }
10674 |
10675 | void bnxt_tx_enable(struct bnxt *bp)
10676 | {
10677 |  int i;
10678 |  struct bnxt_tx_ring_info *txr;
10679 |
10680 |  for (i = 0; i < bp->tx_nr_rings; i++) {
10681 | 		txr = &bp->tx_ring[i];
10682 |  WRITE_ONCE(txr->dev_state, 0);
10683 | 	}
10684 |  /* Make sure napi polls see @dev_state change */
10685 | 	synchronize_net();
10686 | 	netif_tx_wake_all_queues(bp->dev);
10687 |  if (BNXT_LINK_IS_UP(bp))
10688 | 		netif_carrier_on(bp->dev);
10689 | }
10690 |
10691 | static char *bnxt_report_fec(struct bnxt_link_info *link_info)
10692 | {
10693 | 	u8 active_fec = link_info->active_fec_sig_mode &
10694 |  PORT_PHY_QCFG_RESP_ACTIVE_FEC_MASK;
10695 |
10696 |  switch (active_fec) {
10697 |  default:
10698 |  case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_NONE_ACTIVE:
10699 |  return "None";
10700 |  case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_CLAUSE74_ACTIVE:
10701 |  return "Clause 74 BaseR";
10702 |  case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_CLAUSE91_ACTIVE:
11831 | 	bnxt_free_mem(bp, true);
11832 | 	clear_bit(BNXT_STATE_HALF_OPEN, &bp->state);
11833 | }
11834 |
11835 | void bnxt_reenable_sriov(struct bnxt *bp)
11836 | {
11837 |  if (BNXT_PF(bp)) {
11838 |  struct bnxt_pf_info *pf = &bp->pf;
11839 |  int n = pf->active_vfs;
11840 |
11841 |  if (n)
11842 | 			bnxt_cfg_hw_sriov(bp, &n, true);
11843 | 	}
11844 | }
11845 |
11846 | static int bnxt_open(struct net_device *dev)
11847 | {
11848 |  struct bnxt *bp = netdev_priv(dev);
11849 |  int rc;
11850 |
11851 |  if (test_bit(BNXT_STATE_ABORT_ERR, &bp->state)) {
11852 | 		rc = bnxt_reinit_after_abort(bp);
11853 |  if (rc) {
11854 |  if (rc == -EBUSY)
11855 | 				netdev_err(bp->dev, "A previous firmware reset has not completed, aborting\n");
11856 |  else
11857 | 				netdev_err(bp->dev, "Failed to reinitialize after aborted firmware reset\n");
11858 |  return -ENODEV;
11859 | 		}
11860 | 	}
11861 |
11862 | 	rc = bnxt_hwrm_if_change(bp, true);
11863 |  if (rc)
11864 |  return rc;
11865 |
11866 | 	rc = __bnxt_open_nic(bp, true, true);
11867 |  if (rc) {
11868 | 		bnxt_hwrm_if_change(bp, false);
11869 | 	} else {
11870 |  if (test_and_clear_bit(BNXT_STATE_FW_RESET_DET, &bp->state)) {
11871 |  if (!test_bit(BNXT_STATE_IN_FW_RESET, &bp->state)) {
11872 | 				bnxt_ulp_start(bp, 0);
11873 | 				bnxt_reenable_sriov(bp);
11874 | 			}
11875 | 		}
11876 | 	}
11877 |
11878 |  return rc;
11879 | }
11880 |
11881 | static bool bnxt_drv_busy(struct bnxt *bp)
11882 | {
11883 |  return (test_bit(BNXT_STATE_IN_SP_TASK, &bp->state) ||
11884 |  test_bit(BNXT_STATE_READ_STATS, &bp->state));
11885 | }
11886 |
11887 | static void bnxt_get_ring_stats(struct bnxt *bp,
11888 |  struct rtnl_link_stats64 *stats);
11889 |
11890 | static void __bnxt_close_nic(struct bnxt *bp, bool irq_re_init,
11891 | 			     bool link_re_init)
11892 | {
11893 |  /* Close the VF-reps before closing PF */
11894 |  if (BNXT_PF(bp))
    9←Assuming the condition is false→
    10←Taking false branch→
11895 | 		bnxt_vf_reps_close(bp);
11896 |
11897 |  /* Change device state to avoid TX queue wake up's */
11898 |  bnxt_tx_disable(bp);
11899 |
11900 | 	clear_bit(BNXT_STATE_OPEN, &bp->state);
11901 |  smp_mb__after_atomic();
    11←Loop condition is false.  Exiting loop→
    12←Loop condition is false.  Exiting loop→
    13←Loop condition is false.  Exiting loop→
11902 |  while (bnxt_drv_busy(bp))
    14←Loop condition is false. Execution continues on line 11906→
11903 | 		msleep(20);
11904 |
11905 |  /* Flush rings and disable interrupts */
11906 |  bnxt_shutdown_nic(bp, irq_re_init);
11907 |
11908 |  /* TODO CHIMP_FW: Link/PHY related cleanup if (link_re_init) */
11909 |
11910 | 	bnxt_debug_dev_exit(bp);
11911 | 	bnxt_disable_napi(bp);
11912 | 	del_timer_sync(&bp->timer);
11913 |  bnxt_free_skbs(bp);
    15←Calling 'bnxt_free_skbs'→
11914 |
11915 |  /* Save ring stats before shutdown */
11916 |  if (bp->bnapi && irq_re_init) {
11917 | 		bnxt_get_ring_stats(bp, &bp->net_stats_prev);
11918 | 		bnxt_get_ring_err_stats(bp, &bp->ring_err_stats_prev);
11919 | 	}
11920 |  if (irq_re_init) {
11921 | 		bnxt_free_irq(bp);
11922 | 		bnxt_del_napi(bp);
11923 | 	}
11924 | 	bnxt_free_mem(bp, irq_re_init);
11925 | }
11926 |
11927 | void bnxt_close_nic(struct bnxt *bp, bool irq_re_init, bool link_re_init)
11928 | {
11929 |  if (test_bit(BNXT_STATE_IN_FW_RESET, &bp->state)) {
11930 |  /* If we get here, it means firmware reset is in progress
11931 |  * while we are trying to close.  We can safely proceed with
11932 |  * the close because we are holding rtnl_lock().  Some firmware
11933 |  * messages may fail as we proceed to close.  We set the
11934 |  * ABORT_ERR flag here so that the FW reset thread will later
11935 |  * abort when it gets the rtnl_lock() and sees the flag.
11936 |  */
11937 | 		netdev_warn(bp->dev, "FW reset in progress during close, FW reset will be aborted\n");
11938 | 		set_bit(BNXT_STATE_ABORT_ERR, &bp->state);
11939 | 	}
11940 |
11941 | #ifdef CONFIG_BNXT_SRIOV
11942 |  if (bp->sriov_cfg) {
11943 |  int rc;
15318 | 	}
15319 | 	rc = bnxt_hwrm_func_reset(bp);
15320 |  if (rc) {
15321 | 		rc = -EBUSY;
15322 |  goto resume_exit;
15323 | 	}
15324 |
15325 | 	rc = bnxt_hwrm_func_qcaps(bp);
15326 |  if (rc)
15327 |  goto resume_exit;
15328 |
15329 | 	bnxt_clear_reservations(bp, true);
15330 |
15331 |  if (bnxt_hwrm_func_drv_rgtr(bp, NULL, 0, false)) {
15332 | 		rc = -ENODEV;
15333 |  goto resume_exit;
15334 | 	}
15335 |
15336 | 	bnxt_get_wol_settings(bp);
15337 |  if (netif_running(dev)) {
15338 | 		rc = bnxt_open(dev);
15339 |  if (!rc)
15340 | 			netif_device_attach(dev);
15341 | 	}
15342 |
15343 | resume_exit:
15344 | 	bnxt_ulp_start(bp, rc);
15345 |  if (!rc)
15346 | 		bnxt_reenable_sriov(bp);
15347 | 	rtnl_unlock();
15348 |  return rc;
15349 | }
15350 |
15351 | static SIMPLE_DEV_PM_OPS(bnxt_pm_ops, bnxt_suspend, bnxt_resume);
15352 | #define BNXT_PM_OPS (&bnxt_pm_ops)
15353 |
15354 | #else
15355 |
15356 | #define BNXT_PM_OPS NULL
15357 |
15358 | #endif /* CONFIG_PM_SLEEP */
15359 |
15360 | /**
15361 |  * bnxt_io_error_detected - called when PCI error is detected
15362 |  * @pdev: Pointer to PCI device
15363 |  * @state: The current pci connection state
15364 |  *
15365 |  * This function is called after a PCI bus error affecting
15366 |  * this device has been detected.
15367 |  */
15368 | static pci_ers_result_t bnxt_io_error_detected(struct pci_dev *pdev,
15369 | 					       pci_channel_state_t state)
15370 | {
15371 |  struct net_device *netdev = pci_get_drvdata(pdev);
15372 |  struct bnxt *bp = netdev_priv(netdev);
15373 | 	bool abort = false;
15374 |
15375 | 	netdev_info(netdev, "PCI I/O error detected\n");
15376 |
15377 | 	rtnl_lock();
15378 | 	netif_device_detach(netdev);
15379 |
15380 | 	bnxt_ulp_stop(bp);
15381 |
15382 |  if (test_and_set_bit(BNXT_STATE_IN_FW_RESET, &bp->state)) {
    1Assuming the condition is false→
15383 | 		netdev_err(bp->dev, "Firmware reset already in progress\n");
15384 | 		abort = true;
15385 | 	}
15386 |
15387 |  if (abort1.1'abort' is false1.1'abort' is false || state == pci_channel_io_perm_failure) {
    2←Assuming 'state' is not equal to pci_channel_io_perm_failure→
    3←Taking false branch→
15388 | 		rtnl_unlock();
15389 |  return PCI_ERS_RESULT_DISCONNECT;
15390 | 	}
15391 |
15392 |  /* Link is not reliable anymore if state is pci_channel_io_frozen
15393 |  * so we disable bus master to prevent any potential bad DMAs before
15394 |  * freeing kernel memory.
15395 |  */
15396 |  if (state == pci_channel_io_frozen) {
    4←Assuming 'state' is not equal to pci_channel_io_frozen→
    5←Taking false branch→
15397 | 		set_bit(BNXT_STATE_PCI_CHANNEL_IO_FROZEN, &bp->state);
15398 | 		bnxt_fw_fatal_close(bp);
15399 | 	}
15400 |
15401 |  if (netif_running(netdev))
    6←Assuming the condition is true→
    7←Taking true branch→
15402 |  __bnxt_close_nic(bp, true, true);
    8←Calling '__bnxt_close_nic'→
15403 |
15404 |  if (pci_is_enabled(pdev))
15405 | 		pci_disable_device(pdev);
15406 | 	bnxt_free_ctx_mem(bp);
15407 | 	rtnl_unlock();
15408 |
15409 |  /* Request a slot slot reset. */
15410 |  return PCI_ERS_RESULT_NEED_RESET;
15411 | }
15412 |
15413 | /**
15414 |  * bnxt_io_slot_reset - called after the pci bus has been reset.
15415 |  * @pdev: Pointer to PCI device
15416 |  *
15417 |  * Restart the card from scratch, as if from a cold-boot.
15418 |  * At this point, the card has exprienced a hard reset,
15419 |  * followed by fixups by BIOS, and has its config space
15420 |  * set up identically to what it was at cold boot.
15421 |  */
15422 | static pci_ers_result_t bnxt_io_slot_reset(struct pci_dev *pdev)
15423 | {
15424 | 	pci_ers_result_t result = PCI_ERS_RESULT_DISCONNECT;
15425 |  struct net_device *netdev = pci_get_drvdata(pdev);
15426 |  struct bnxt *bp = netdev_priv(netdev);
15427 |  int retry = 0;
15428 |  int err = 0;
15429 |  int off;
15430 |
15431 | 	netdev_info(bp->dev, "PCI Slot Reset\n");
15432 |
235   |
236   | static inline long page_pool_unref_page(struct page *page, long nr)
237   | {
238   |  long ret;
239   |
240   |  /* If nr == pp_ref_count then we have cleared all remaining
241   |  * references to the page:
242   |  * 1. 'n == 1': no need to actually overwrite it.
243   |  * 2. 'n != 1': overwrite it with one, which is the rare case
244   |  *              for pp_ref_count draining.
245   |  *
246   |  * The main advantage to doing this is that not only we avoid a atomic
247   |  * update, as an atomic_read is generally a much cheaper operation than
248   |  * an atomic update, especially when dealing with a page that may be
249   |  * referenced by only 2 or 3 users; but also unify the pp_ref_count
250   |  * handling by ensuring all pages have partitioned into only 1 piece
251   |  * initially, and only overwrite it when the page is partitioned into
252   |  * more than one piece.
253   |  */
254   |  if (atomic_long_read(&page->pp_ref_count) == nr) {
255   |  /* As we have ensured nr is always one for constant case using
256   |  * the BUILD_BUG_ON(), only need to handle the non-constant case
257   |  * here for pp_ref_count draining, which is a rare case.
258   |  */
259   |  BUILD_BUG_ON(__builtin_constant_p(nr) && nr != 1);
260   |  if (!__builtin_constant_p(nr))
261   | 			atomic_long_set(&page->pp_ref_count, 1);
262   |
263   |  return 0;
264   | 	}
265   |
266   | 	ret = atomic_long_sub_return(nr, &page->pp_ref_count);
267   |  WARN_ON(ret < 0);
268   |
269   |  /* We are the last user here too, reset pp_ref_count back to 1 to
270   |  * ensure all pages have been partitioned into 1 piece initially,
271   |  * this should be the rare case when the last two fragment users call
272   |  * page_pool_unref_page() currently.
273   |  */
274   |  if (unlikely(!ret))
275   | 		atomic_long_set(&page->pp_ref_count, 1);
276   |
277   |  return ret;
278   | }
279   |
280   | static inline void page_pool_ref_page(struct page *page)
281   | {
282   | 	atomic_long_inc(&page->pp_ref_count);
283   | }
284   |
285   | static inline bool page_pool_is_last_ref(struct page *page)
286   | {
287   |  /* If page_pool_unref_page() returns 0, we were the last user */
288   |  return page_pool_unref_page(page, 1) == 0;
289   | }
290   |
291   | /**
292   |  * page_pool_put_page() - release a reference to a page pool page
293   |  * @pool:	pool from which page was allocated
294   |  * @page:	page to release a reference on
295   |  * @dma_sync_size: how much of the page may have been touched by the device
296   |  * @allow_direct: released by the consumer, allow lockless caching
297   |  *
298   |  * The outcome of this depends on the page refcnt. If the driver bumps
299   |  * the refcnt > 1 this will unmap the page. If the page refcnt is 1
300   |  * the allocator owns the page and will try to recycle it in one of the pool
301   |  * caches. If PP_FLAG_DMA_SYNC_DEV is set, the page will be synced for_device
302   |  * using dma_sync_single_range_for_device().
303   |  */
304   | static inline void page_pool_put_page(struct page_pool *pool,
305   |  struct page *page,
306   |  unsigned int dma_sync_size,
307   | 				      bool allow_direct)
308   | {
309   |  /* When page_pool isn't compiled-in, net/core/xdp.c doesn't
310   |  * allow registering MEM_TYPE_PAGE_POOL, but shield linker.
311   |  */
312   | #ifdef CONFIG_PAGE_POOL
313   |  if (!page_pool_is_last_ref(page))
    36←Taking false branch→
314   |  return;
315   |
316   |  page_pool_put_unrefed_page(pool, page, dma_sync_size, allow_direct);
    37←Missing hwrm_req_drop() after successful hwrm_req_init()
317   | #endif
318   | }
319   |
320   | /**
321   |  * page_pool_put_full_page() - release a reference on a page pool page
322   |  * @pool:	pool from which page was allocated
323   |  * @page:	page to release a reference on
324   |  * @allow_direct: released by the consumer, allow lockless caching
325   |  *
326   |  * Similar to page_pool_put_page(), but will DMA sync the entire memory area
327   |  * as configured in &page_pool_params.max_len.
328   |  */
329   | static inline void page_pool_put_full_page(struct page_pool *pool,
330   |  struct page *page, bool allow_direct)
331   | {
332   |  page_pool_put_page(pool, page, -1, allow_direct);
    35←Calling 'page_pool_put_page'→
333   | }
334   |
335   | /**
336   |  * page_pool_recycle_direct() - release a reference on a page pool page
337   |  * @pool:	pool from which page was allocated
338   |  * @page:	page to release a reference on
339   |  *
340   |  * Similar to page_pool_put_full_page() but caller must guarantee safe context
341   |  * (e.g NAPI), since it will recycle the page directly into the pool fast cache.
342   |  */
343   | static inline void page_pool_recycle_direct(struct page_pool *pool,
344   |  struct page *page)
345   | {
346   |  page_pool_put_full_page(pool, page, true);
    34←Calling 'page_pool_put_full_page'→
347   | }
348   |
349   | #define PAGE_POOL_32BIT_ARCH_WITH_64BIT_DMA	\
350   |  (sizeof(dma_addr_t) > sizeof(unsigned long))
351   |
352   | /**
353   |  * page_pool_free_va() - free a va into the page_pool
354   |  * @pool: pool from which va was allocated
355   |  * @va: va to be freed
356   |  * @allow_direct: freed by the consumer, allow lockless caching
357   |  *
358   |  * Free a va allocated from page_pool_allo_va().
359   |  */
360   | static inline void page_pool_free_va(struct page_pool *pool, void *va,
361   | 				     bool allow_direct)
362   | {
363   | 	page_pool_put_page(pool, virt_to_head_page(va), -1, allow_direct);
364   | }
365   |
366   | /**
367   |  * page_pool_get_dma_addr() - Retrieve the stored DMA address.
368   |  * @page:	page allocated from a page pool
369   |  *
370   |  * Fetch the DMA address of the page. The page pool to which the page belongs
371   |  * must had been created with PP_FLAG_DMA_MAP.
372   |  */
373   | static inline dma_addr_t page_pool_get_dma_addr(struct page *page)
374   | {
375   | 	dma_addr_t ret = page->dma_addr;
376   |

Analysis:
- Decision: NotABug
- Reason: The reported location (include/net/page_pool/helpers.h, around line 316) is within the generic page pool helpers (page_pool_put_page and related functions) and contains no calls to hwrm_req_init(), hwrm_req_replace(), or hwrm_req_drop(). The target bug pattern specifically concerns missing hwrm_req_drop() after a successful hwrm_req_init() in BNXT HWRM request handling. Since the flagged code path is unrelated to HWRM requests and contains no such allocation/cleanup sequence, it does not match the target bug pattern and thus is a false positive.

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
