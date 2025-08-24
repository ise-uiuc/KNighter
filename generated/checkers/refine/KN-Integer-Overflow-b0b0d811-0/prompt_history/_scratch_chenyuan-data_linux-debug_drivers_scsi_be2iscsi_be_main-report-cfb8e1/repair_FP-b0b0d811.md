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

Performing a multiplication on operands of narrower or mixed integer types (e.g., u32 × u32, int × unsigned int) and then assigning/adding the result to a wider type (u64/dma_addr_t) without first promoting an operand to the wider type. This causes the multiplication to occur in the narrower type and potentially overflow before being widened, e.g.:

- args->size = args->pitch * args->height;        // u32 * u32 -> overflow before storing in u64
- addr += (src_x >> 16) * cpp;                     // int * u8/u32 -> overflow before adding to dma_addr_t
- addr += pitch * y_offset_in_blocks;              // u32 * int -> overflow before adding to dma_addr_t

Fix by ensuring the multiplication is done in a wide enough type (cast one operand or use a wide-typed accumulator first), e.g., size64 = (u64)pitch32 * height32; or size64 = pitch32; size64 *= height32.

The patch that needs to be detected:

## Patch Description

drm/mediatek: Fix coverity issue with unintentional integer overflow

1. Instead of multiplying 2 variable of different types. Change to
assign a value of one variable and then multiply the other variable.

2. Add a int variable for multiplier calculation instead of calculating
different types multiplier with dma_addr_t variable directly.

Fixes: 1a64a7aff8da ("drm/mediatek: Fix cursor plane no update")
Signed-off-by: Jason-JH.Lin <jason-jh.lin@mediatek.com>
Reviewed-by: Alexandre Mergnat <amergnat@baylibre.com>
Reviewed-by: AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>
Link: https://patchwork.kernel.org/project/dri-devel/patch/20230907091425.9526-1-jason-jh.lin@mediatek.com/
Signed-off-by: Chun-Kuang Hu <chunkuang.hu@kernel.org>

## Buggy Code

```c
// Function: mtk_plane_update_new_state in drivers/gpu/drm/mediatek/mtk_drm_plane.c
static void mtk_plane_update_new_state(struct drm_plane_state *new_state,
				       struct mtk_plane_state *mtk_plane_state)
{
	struct drm_framebuffer *fb = new_state->fb;
	struct drm_gem_object *gem;
	struct mtk_drm_gem_obj *mtk_gem;
	unsigned int pitch, format;
	u64 modifier;
	dma_addr_t addr;
	dma_addr_t hdr_addr = 0;
	unsigned int hdr_pitch = 0;

	gem = fb->obj[0];
	mtk_gem = to_mtk_gem_obj(gem);
	addr = mtk_gem->dma_addr;
	pitch = fb->pitches[0];
	format = fb->format->format;
	modifier = fb->modifier;

	if (modifier == DRM_FORMAT_MOD_LINEAR) {
		addr += (new_state->src.x1 >> 16) * fb->format->cpp[0];
		addr += (new_state->src.y1 >> 16) * pitch;
	} else {
		int width_in_blocks = ALIGN(fb->width, AFBC_DATA_BLOCK_WIDTH)
				      / AFBC_DATA_BLOCK_WIDTH;
		int height_in_blocks = ALIGN(fb->height, AFBC_DATA_BLOCK_HEIGHT)
				       / AFBC_DATA_BLOCK_HEIGHT;
		int x_offset_in_blocks = (new_state->src.x1 >> 16) / AFBC_DATA_BLOCK_WIDTH;
		int y_offset_in_blocks = (new_state->src.y1 >> 16) / AFBC_DATA_BLOCK_HEIGHT;
		int hdr_size;

		hdr_pitch = width_in_blocks * AFBC_HEADER_BLOCK_SIZE;
		pitch = width_in_blocks * AFBC_DATA_BLOCK_WIDTH *
			AFBC_DATA_BLOCK_HEIGHT * fb->format->cpp[0];

		hdr_size = ALIGN(hdr_pitch * height_in_blocks, AFBC_HEADER_ALIGNMENT);

		hdr_addr = addr + hdr_pitch * y_offset_in_blocks +
			   AFBC_HEADER_BLOCK_SIZE * x_offset_in_blocks;
		/* The data plane is offset by 1 additional block. */
		addr = addr + hdr_size +
		       pitch * y_offset_in_blocks +
		       AFBC_DATA_BLOCK_WIDTH * AFBC_DATA_BLOCK_HEIGHT *
		       fb->format->cpp[0] * (x_offset_in_blocks + 1);
	}

	mtk_plane_state->pending.enable = true;
	mtk_plane_state->pending.pitch = pitch;
	mtk_plane_state->pending.hdr_pitch = hdr_pitch;
	mtk_plane_state->pending.format = format;
	mtk_plane_state->pending.modifier = modifier;
	mtk_plane_state->pending.addr = addr;
	mtk_plane_state->pending.hdr_addr = hdr_addr;
	mtk_plane_state->pending.x = new_state->dst.x1;
	mtk_plane_state->pending.y = new_state->dst.y1;
	mtk_plane_state->pending.width = drm_rect_width(&new_state->dst);
	mtk_plane_state->pending.height = drm_rect_height(&new_state->dst);
	mtk_plane_state->pending.rotation = new_state->rotation;
	mtk_plane_state->pending.color_encoding = new_state->color_encoding;
}
```

```c
// Function: mtk_drm_gem_dumb_create in drivers/gpu/drm/mediatek/mtk_drm_gem.c
int mtk_drm_gem_dumb_create(struct drm_file *file_priv, struct drm_device *dev,
			    struct drm_mode_create_dumb *args)
{
	struct mtk_drm_gem_obj *mtk_gem;
	int ret;

	args->pitch = DIV_ROUND_UP(args->width * args->bpp, 8);
	args->size = args->pitch * args->height;

	mtk_gem = mtk_drm_gem_create(dev, args->size, false);
	if (IS_ERR(mtk_gem))
		return PTR_ERR(mtk_gem);

	/*
	 * allocate a id of idr table where the obj is registered
	 * and handle has the id what user can see.
	 */
	ret = drm_gem_handle_create(file_priv, &mtk_gem->base, &args->handle);
	if (ret)
		goto err_handle_create;

	/* drop reference from allocate - handle holds it now. */
	drm_gem_object_put(&mtk_gem->base);

	return 0;

err_handle_create:
	mtk_drm_gem_free_object(&mtk_gem->base);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/mediatek/mtk_drm_gem.c b/drivers/gpu/drm/mediatek/mtk_drm_gem.c
index 9f364df52478..f6632a0fe509 100644
--- a/drivers/gpu/drm/mediatek/mtk_drm_gem.c
+++ b/drivers/gpu/drm/mediatek/mtk_drm_gem.c
@@ -121,7 +121,14 @@ int mtk_drm_gem_dumb_create(struct drm_file *file_priv, struct drm_device *dev,
 	int ret;

 	args->pitch = DIV_ROUND_UP(args->width * args->bpp, 8);
-	args->size = args->pitch * args->height;
+
+	/*
+	 * Multiply 2 variables of different types,
+	 * for example: args->size = args->spacing * args->height;
+	 * may cause coverity issue with unintentional overflow.
+	 */
+	args->size = args->pitch;
+	args->size *= args->height;

 	mtk_gem = mtk_drm_gem_create(dev, args->size, false);
 	if (IS_ERR(mtk_gem))
diff --git a/drivers/gpu/drm/mediatek/mtk_drm_plane.c b/drivers/gpu/drm/mediatek/mtk_drm_plane.c
index db2f70ae060d..5acb03b7c6fe 100644
--- a/drivers/gpu/drm/mediatek/mtk_drm_plane.c
+++ b/drivers/gpu/drm/mediatek/mtk_drm_plane.c
@@ -141,6 +141,7 @@ static void mtk_plane_update_new_state(struct drm_plane_state *new_state,
 	dma_addr_t addr;
 	dma_addr_t hdr_addr = 0;
 	unsigned int hdr_pitch = 0;
+	int offset;

 	gem = fb->obj[0];
 	mtk_gem = to_mtk_gem_obj(gem);
@@ -150,8 +151,15 @@ static void mtk_plane_update_new_state(struct drm_plane_state *new_state,
 	modifier = fb->modifier;

 	if (modifier == DRM_FORMAT_MOD_LINEAR) {
-		addr += (new_state->src.x1 >> 16) * fb->format->cpp[0];
-		addr += (new_state->src.y1 >> 16) * pitch;
+		/*
+		 * Using dma_addr_t variable to calculate with multiplier of different types,
+		 * for example: addr += (new_state->src.x1 >> 16) * fb->format->cpp[0];
+		 * may cause coverity issue with unintentional overflow.
+		 */
+		offset = (new_state->src.x1 >> 16) * fb->format->cpp[0];
+		addr += offset;
+		offset = (new_state->src.y1 >> 16) * pitch;
+		addr += offset;
 	} else {
 		int width_in_blocks = ALIGN(fb->width, AFBC_DATA_BLOCK_WIDTH)
 				      / AFBC_DATA_BLOCK_WIDTH;
@@ -159,21 +167,34 @@ static void mtk_plane_update_new_state(struct drm_plane_state *new_state,
 				       / AFBC_DATA_BLOCK_HEIGHT;
 		int x_offset_in_blocks = (new_state->src.x1 >> 16) / AFBC_DATA_BLOCK_WIDTH;
 		int y_offset_in_blocks = (new_state->src.y1 >> 16) / AFBC_DATA_BLOCK_HEIGHT;
-		int hdr_size;
+		int hdr_size, hdr_offset;

 		hdr_pitch = width_in_blocks * AFBC_HEADER_BLOCK_SIZE;
 		pitch = width_in_blocks * AFBC_DATA_BLOCK_WIDTH *
 			AFBC_DATA_BLOCK_HEIGHT * fb->format->cpp[0];

 		hdr_size = ALIGN(hdr_pitch * height_in_blocks, AFBC_HEADER_ALIGNMENT);
+		hdr_offset = hdr_pitch * y_offset_in_blocks +
+			AFBC_HEADER_BLOCK_SIZE * x_offset_in_blocks;
+
+		/*
+		 * Using dma_addr_t variable to calculate with multiplier of different types,
+		 * for example: addr += hdr_pitch * y_offset_in_blocks;
+		 * may cause coverity issue with unintentional overflow.
+		 */
+		hdr_addr = addr + hdr_offset;

-		hdr_addr = addr + hdr_pitch * y_offset_in_blocks +
-			   AFBC_HEADER_BLOCK_SIZE * x_offset_in_blocks;
 		/* The data plane is offset by 1 additional block. */
-		addr = addr + hdr_size +
-		       pitch * y_offset_in_blocks +
-		       AFBC_DATA_BLOCK_WIDTH * AFBC_DATA_BLOCK_HEIGHT *
-		       fb->format->cpp[0] * (x_offset_in_blocks + 1);
+		offset = pitch * y_offset_in_blocks +
+			 AFBC_DATA_BLOCK_WIDTH * AFBC_DATA_BLOCK_HEIGHT *
+			 fb->format->cpp[0] * (x_offset_in_blocks + 1);
+
+		/*
+		 * Using dma_addr_t variable to calculate with multiplier of different types,
+		 * for example: addr += pitch * y_offset_in_blocks;
+		 * may cause coverity issue with unintentional overflow.
+		 */
+		addr = addr + hdr_size + offset;
 	}

 	mtk_plane_state->pending.enable = true;
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/drivers/scsi/be2iscsi/be_main.c
---|---
Warning:| line 2897, column 39
Multiplication occurs in a narrower type and is widened after; possible
overflow before assignment/addition to wide type

### Annotated Source Code


2667  | 			idx++;
2668  | 		}
2669  | 		pwrb_context->alloc_index = 0;
2670  | 		pwrb_context->wrb_handles_available = 0;
2671  | 		pwrb_context->free_index = 0;
2672  |
2673  |  if (num_cxn_wrbh) {
2674  |  for (j = 0; j < phba->params.wrbs_per_cxn; j++) {
2675  | 				pwrb_context->pwrb_handle_base[j] = pwrb_handle;
2676  | 				pwrb_context->pwrb_handle_basestd[j] =
2677  | 								pwrb_handle;
2678  | 				pwrb_context->wrb_handles_available++;
2679  | 				pwrb_handle->wrb_index = j;
2680  | 				pwrb_handle++;
2681  | 			}
2682  | 			num_cxn_wrbh--;
2683  | 		}
2684  |  spin_lock_init(&pwrb_context->wrb_lock);
2685  | 	}
2686  | 	idx = 0;
2687  |  for (index = 0; index < phba->params.cxns_per_ctrl; index++) {
2688  | 		pwrb_context = &phwi_ctrlr->wrb_context[index];
2689  |  if (!num_cxn_wrb) {
2690  | 			pwrb = mem_descr_wrb->mem_array[idx].virtual_address;
2691  | 			num_cxn_wrb = (mem_descr_wrb->mem_array[idx].size) /
2692  | 				((sizeof(struct iscsi_wrb) *
2693  | 				  phba->params.wrbs_per_cxn));
2694  | 			idx++;
2695  | 		}
2696  |
2697  |  if (num_cxn_wrb) {
2698  |  for (j = 0; j < phba->params.wrbs_per_cxn; j++) {
2699  | 				pwrb_handle = pwrb_context->pwrb_handle_base[j];
2700  | 				pwrb_handle->pwrb = pwrb;
2701  | 				pwrb++;
2702  | 			}
2703  | 			num_cxn_wrb--;
2704  | 		}
2705  | 	}
2706  |  return 0;
2707  | init_wrb_hndl_failed:
2708  |  for (j = index; j > 0; j--) {
2709  | 		pwrb_context = &phwi_ctrlr->wrb_context[j];
2710  | 		kfree(pwrb_context->pwrb_handle_base);
2711  | 		kfree(pwrb_context->pwrb_handle_basestd);
2712  | 	}
2713  | 	kfree(phwi_ctxt->be_wrbq);
2714  |  return -ENOMEM;
2715  | }
2716  |
2717  | static int hwi_init_async_pdu_ctx(struct beiscsi_hba *phba)
2718  | {
2719  |  uint8_t ulp_num;
2720  |  struct hwi_controller *phwi_ctrlr;
2721  |  struct hba_parameters *p = &phba->params;
2722  |  struct hd_async_context *pasync_ctx;
2723  |  struct hd_async_handle *pasync_header_h, *pasync_data_h;
2724  |  unsigned int index, idx, num_per_mem, num_async_data;
2725  |  struct be_mem_descriptor *mem_descr;
2726  |
2727  |  for (ulp_num = 0; ulp_num < BEISCSI_ULP_COUNT; ulp_num++) {
2728  |  if (test_bit(ulp_num, &phba->fw_config.ulp_supported)) {
    1Loop condition is true.  Entering loop body→
    2←Assuming the condition is true→
    3←Taking true branch→
2729  |  /* get async_ctx for each ULP */
2730  |  mem_descr = (struct be_mem_descriptor *)phba->init_mem;
2731  | 			mem_descr += (HWI_MEM_ASYNC_PDU_CONTEXT_ULP0 +
2732  | 				     (ulp_num * MEM_DESCR_OFFSET));
2733  |
2734  | 			phwi_ctrlr = phba->phwi_ctrlr;
2735  | 			phwi_ctrlr->phwi_ctxt->pasync_ctx[ulp_num] =
2736  | 				(struct hd_async_context *)
2737  | 				 mem_descr->mem_array[0].virtual_address;
2738  |
2739  | 			pasync_ctx = phwi_ctrlr->phwi_ctxt->pasync_ctx[ulp_num];
2740  |  memset(pasync_ctx, 0, sizeof(*pasync_ctx));
2741  |
2742  | 			pasync_ctx->async_entry =
2743  | 					(struct hd_async_entry *)
2744  | 					((long unsigned int)pasync_ctx +
2745  |  sizeof(struct hd_async_context));
2746  |
2747  | 			pasync_ctx->num_entries = BEISCSI_ASYNC_HDQ_SIZE(phba,
2748  |  ulp_num);
2749  |  /* setup header buffers */
2750  | 			mem_descr = (struct be_mem_descriptor *)phba->init_mem;
2751  | 			mem_descr += HWI_MEM_ASYNC_HEADER_BUF_ULP0 +
2752  | 				(ulp_num * MEM_DESCR_OFFSET);
2753  |  if (mem_descr->mem_array[0].virtual_address) {
    4←Assuming field 'virtual_address' is null→
    5←Taking false branch→
2754  |  beiscsi_log(phba, KERN_INFO, BEISCSI_LOG_INIT,
2755  |  "BM_%d : hwi_init_async_pdu_ctx"
2756  |  " HWI_MEM_ASYNC_HEADER_BUF_ULP%d va=%p\n",
2757  |  ulp_num,
2758  |  mem_descr->mem_array[0].
2759  |  virtual_address);
2760  | 			} else
2761  |  beiscsi_log(phba, KERN_WARNING,
    6←Assuming the condition is false→
    7←Taking false branch→
    8←Loop condition is false.  Exiting loop→
2762  |  BEISCSI_LOG_INIT,
2763  |  "BM_%d : No Virtual address for ULP : %d\n",
2764  |  ulp_num);
2765  |
2766  |  pasync_ctx->async_header.pi = 0;
2767  | 			pasync_ctx->async_header.buffer_size = p->defpdu_hdr_sz;
2768  | 			pasync_ctx->async_header.va_base =
2769  | 				mem_descr->mem_array[0].virtual_address;
2770  |
2771  | 			pasync_ctx->async_header.pa_base.u.a64.address =
2772  | 				mem_descr->mem_array[0].
2773  | 				bus_address.u.a64.address;
2774  |
2775  |  /* setup header buffer sgls */
2776  | 			mem_descr = (struct be_mem_descriptor *)phba->init_mem;
2777  | 			mem_descr += HWI_MEM_ASYNC_HEADER_RING_ULP0 +
2778  | 				     (ulp_num * MEM_DESCR_OFFSET);
2779  |  if (mem_descr->mem_array[0].virtual_address) {
    9←Assuming field 'virtual_address' is null→
    10←Taking false branch→
2780  |  beiscsi_log(phba, KERN_INFO, BEISCSI_LOG_INIT,
2781  |  "BM_%d : hwi_init_async_pdu_ctx"
2782  |  " HWI_MEM_ASYNC_HEADER_RING_ULP%d va=%p\n",
2783  |  ulp_num,
2784  |  mem_descr->mem_array[0].
2785  |  virtual_address);
2786  | 			} else
2787  |  beiscsi_log(phba, KERN_WARNING,
    11←Taking false branch→
    12←Loop condition is false.  Exiting loop→
2788  |  BEISCSI_LOG_INIT,
2789  |  "BM_%d : No Virtual address for ULP : %d\n",
2790  |  ulp_num);
2791  |
2792  |  pasync_ctx->async_header.ring_base =
2793  |  mem_descr->mem_array[0].virtual_address;
2794  |
2795  |  /* setup header buffer handles */
2796  |  mem_descr = (struct be_mem_descriptor *)phba->init_mem;
2797  | 			mem_descr += HWI_MEM_ASYNC_HEADER_HANDLE_ULP0 +
2798  | 				     (ulp_num * MEM_DESCR_OFFSET);
2799  |  if (mem_descr->mem_array[0].virtual_address) {
    13←Assuming field 'virtual_address' is non-null→
    14←Taking true branch→
2800  |  beiscsi_log(phba, KERN_INFO, BEISCSI_LOG_INIT,
    15←Taking false branch→
    16←Loop condition is false.  Exiting loop→
2801  |  "BM_%d : hwi_init_async_pdu_ctx"
2802  |  " HWI_MEM_ASYNC_HEADER_HANDLE_ULP%d va=%p\n",
2803  |  ulp_num,
2804  |  mem_descr->mem_array[0].
2805  |  virtual_address);
2806  | 			} else
2807  |  beiscsi_log(phba, KERN_WARNING,
2808  |  BEISCSI_LOG_INIT,
2809  |  "BM_%d : No Virtual address for ULP : %d\n",
2810  |  ulp_num);
2811  |
2812  |  pasync_ctx->async_header.handle_base =
2813  |  mem_descr->mem_array[0].virtual_address;
2814  |
2815  |  /* setup data buffer sgls */
2816  |  mem_descr = (struct be_mem_descriptor *)phba->init_mem;
2817  | 			mem_descr += HWI_MEM_ASYNC_DATA_RING_ULP0 +
2818  | 				     (ulp_num * MEM_DESCR_OFFSET);
2819  |  if (mem_descr->mem_array[0].virtual_address) {
    17←Assuming field 'virtual_address' is null→
    18←Taking false branch→
2820  |  beiscsi_log(phba, KERN_INFO, BEISCSI_LOG_INIT,
2821  |  "BM_%d : hwi_init_async_pdu_ctx"
2822  |  " HWI_MEM_ASYNC_DATA_RING_ULP%d va=%p\n",
2823  |  ulp_num,
2824  |  mem_descr->mem_array[0].
2825  |  virtual_address);
2826  | 			} else
2827  |  beiscsi_log(phba, KERN_WARNING,
    19←Taking false branch→
    20←Loop condition is false.  Exiting loop→
2828  |  BEISCSI_LOG_INIT,
2829  |  "BM_%d : No Virtual address for ULP : %d\n",
2830  |  ulp_num);
2831  |
2832  |  pasync_ctx->async_data.ring_base =
2833  |  mem_descr->mem_array[0].virtual_address;
2834  |
2835  |  /* setup data buffer handles */
2836  |  mem_descr = (struct be_mem_descriptor *)phba->init_mem;
2837  | 			mem_descr += HWI_MEM_ASYNC_DATA_HANDLE_ULP0 +
2838  | 				     (ulp_num * MEM_DESCR_OFFSET);
2839  |  if (!mem_descr->mem_array[0].virtual_address)
    21←Assuming field 'virtual_address' is non-null→
    22←Taking false branch→
2840  |  beiscsi_log(phba, KERN_WARNING,
2841  |  BEISCSI_LOG_INIT,
2842  |  "BM_%d : No Virtual address for ULP : %d\n",
2843  |  ulp_num);
2844  |
2845  |  pasync_ctx->async_data.handle_base =
2846  |  mem_descr->mem_array[0].virtual_address;
2847  |
2848  |  pasync_header_h =
2849  | 				(struct hd_async_handle *)
2850  | 				pasync_ctx->async_header.handle_base;
2851  | 			pasync_data_h =
2852  | 				(struct hd_async_handle *)
2853  | 				pasync_ctx->async_data.handle_base;
2854  |
2855  |  /* setup data buffers */
2856  | 			mem_descr = (struct be_mem_descriptor *)phba->init_mem;
2857  | 			mem_descr += HWI_MEM_ASYNC_DATA_BUF_ULP0 +
2858  | 				     (ulp_num * MEM_DESCR_OFFSET);
2859  |  if (mem_descr->mem_array[0].virtual_address) {
    23←Assuming field 'virtual_address' is non-null→
    24←Taking true branch→
2860  |  beiscsi_log(phba, KERN_INFO, BEISCSI_LOG_INIT,
    25←Taking false branch→
    26←Loop condition is false.  Exiting loop→
2861  |  "BM_%d : hwi_init_async_pdu_ctx"
2862  |  " HWI_MEM_ASYNC_DATA_BUF_ULP%d va=%p\n",
2863  |  ulp_num,
2864  |  mem_descr->mem_array[0].
2865  |  virtual_address);
2866  | 			} else
2867  |  beiscsi_log(phba, KERN_WARNING,
2868  |  BEISCSI_LOG_INIT,
2869  |  "BM_%d : No Virtual address for ULP : %d\n",
2870  |  ulp_num);
2871  |
2872  |  idx = 0;
2873  | 			pasync_ctx->async_data.pi = 0;
2874  | 			pasync_ctx->async_data.buffer_size = p->defpdu_data_sz;
2875  | 			pasync_ctx->async_data.va_base =
2876  | 				mem_descr->mem_array[idx].virtual_address;
2877  | 			pasync_ctx->async_data.pa_base.u.a64.address =
2878  | 				mem_descr->mem_array[idx].
2879  | 				bus_address.u.a64.address;
2880  |
2881  | 			num_async_data = ((mem_descr->mem_array[idx].size) /
2882  | 					phba->params.defpdu_data_sz);
2883  | 			num_per_mem = 0;
2884  |
2885  |  for (index = 0;	index < BEISCSI_ASYNC_HDQ_SIZE
    27←Assuming the condition is true→
    28←Loop condition is true.  Entering loop body→
2886  |  (phba, ulp_num); index++) {
2887  |  pasync_header_h->cri = -1;
2888  | 				pasync_header_h->is_header = 1;
2889  | 				pasync_header_h->index = index;
2890  | 				INIT_LIST_HEAD(&pasync_header_h->link);
2891  | 				pasync_header_h->pbuffer =
2892  | 					(void *)((unsigned long)
2893  | 						 (pasync_ctx->
2894  | 						  async_header.va_base) +
2895  | 						 (p->defpdu_hdr_sz * index));
2896  |
2897  |  pasync_header_h->pa.u.a64.address =
    29←Multiplication occurs in a narrower type and is widened after; possible overflow before assignment/addition to wide type
2898  | 					pasync_ctx->async_header.pa_base.u.a64.
2899  | 					address + (p->defpdu_hdr_sz * index);
2900  |
2901  | 				pasync_ctx->async_entry[index].header =
2902  | 					pasync_header_h;
2903  | 				pasync_header_h++;
2904  | 				INIT_LIST_HEAD(&pasync_ctx->async_entry[index].
2905  | 						wq.list);
2906  |
2907  | 				pasync_data_h->cri = -1;
2908  | 				pasync_data_h->is_header = 0;
2909  | 				pasync_data_h->index = index;
2910  | 				INIT_LIST_HEAD(&pasync_data_h->link);
2911  |
2912  |  if (!num_async_data) {
2913  | 					num_per_mem = 0;
2914  | 					idx++;
2915  | 					pasync_ctx->async_data.va_base =
2916  | 						mem_descr->mem_array[idx].
2917  | 						virtual_address;
2918  | 					pasync_ctx->async_data.pa_base.u.
2919  | 						a64.address =
2920  | 						mem_descr->mem_array[idx].
2921  | 						bus_address.u.a64.address;
2922  | 					num_async_data =
2923  | 						((mem_descr->mem_array[idx].
2924  | 						  size) /
2925  | 						 phba->params.defpdu_data_sz);
2926  | 				}
2927  | 				pasync_data_h->pbuffer =
2928  | 					(void *)((unsigned long)
2929  | 					(pasync_ctx->async_data.va_base) +

Analysis:
- Decision: NotABug
- Reason: The flagged line computes a 32-bit product (p->defpdu_hdr_sz * index) and adds it to a 64-bit DMA address. While this matches the syntactic pattern of “multiply in a narrower type, then widen,” an actual overflow in the 32-bit product is not feasible given the driver’s bounds:
  - index iterates up to BEISCSI_ASYNC_HDQ_SIZE(phba, ulp_num) − 1, which for this hardware queue is small (typically a few thousand at most; queue sizes in be2iscsi are not near 2^32).
  - p->defpdu_hdr_sz is the default iSCSI PDU header size, which is small (tens to hundreds of bytes; well below even a few kilobytes).
  - Even pessimistically, with index <= ~4096 and defpdu_hdr_sz <= ~2048, the product is <= ~8 MiB, far below 2^32. Thus, no overflow can occur before widening to u64.
  - There is no evidence of a corresponding kernel fix that casts one operand to u64 here, nor is such a fix needed to prevent a real bug under realistic parameter ranges.
Therefore, although the expression is a mixed-width arithmetic pattern, it does not constitute a real bug or match the target bug pattern’s intent (overflow risk before widening).

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
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallString.h"
#include <algorithm>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided externally.
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};
bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

namespace {

class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::PostStmt<DeclStmt>> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
                                     "Mixed-width multiplication may overflow before widening",
                                     "Integer")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;

private:
  // Helpers
  static unsigned getTypeBitWidth(QualType QT, CheckerContext &C);
  static bool isIntegerLike(QualType QT);
  static bool isWideTargetType(QualType QT, CheckerContext &C);
  static bool isConstantFolded(const Expr *E, CheckerContext &C);

  // Range reasoning helpers to suppress FPs when product fits in the mul's type.
  static void getTypeRange128(QualType QT, CheckerContext &C,
                              llvm::APInt &Min, llvm::APInt &Max);
  static bool getExprRange128(const Expr *E, CheckerContext &C,
                              llvm::APInt &Min, llvm::APInt &Max,
                              unsigned Depth = 0);
  static bool productDefinitelyFitsInType(const Expr *L, const Expr *R,
                                          QualType MulType, CheckerContext &C);

  // Finds a suspicious '*' on the value-producing path of Root.
  static bool findFirstSuspiciousMulOnValuePath(const Expr *Root,
                                                unsigned TargetBits,
                                                const BinaryOperator *&OutMul,
                                                CheckerContext &C);

  // Extract a variable/field identifier name from an expression if possible.
  static std::string extractIdentifierLikeName(const Expr *E);

  static bool nameContains(StringRef TextLower,
                           std::initializer_list<StringRef> Needles);

  // Address/size-like LHS filter for intended bug surface.
  static bool isAddressOrSizeLikeLHS(const Expr *LHS);

  // IRQ-like and jiffies contexts suppression.
  static bool isIrqLikeContext(const Expr *Root, const Expr *LHS, CheckerContext &C);

  // Kernel block/folio I/O math suppression helpers
  static bool isShiftOfOne(const Expr *E);
  static bool exprNameContains(const Expr *E, std::initializer_list<StringRef> Needles,
                               CheckerContext &C);
  static bool isBlockSizeLikeExpr(const Expr *E, CheckerContext &C);
  static bool isAddSubChainRec(const Expr *E,
                               std::initializer_list<StringRef> Needles,
                               CheckerContext &C);
  static bool isAddSubChainOfNames(const Expr *E,
                                   std::initializer_list<StringRef> Needles,
                                   CheckerContext &C);
  static bool isBlockCountLikeExpr(const Expr *E, CheckerContext &C);
  static bool isPageOrFolioContext(const Expr *Root, CheckerContext &C);

  // Heuristic: detect known-timeout/jiffies/IRQ contexts to avoid FPs.
  static bool isFalsePositiveContext(const Expr *Root,
                                     const BinaryOperator *MulBO,
                                     const Expr *LHSExpr,
                                     CheckerContext &C);

  // FP suppressors for cases where '*' is not contributing directly to the value
  // assigned/added to the wide type.
  static bool isMulUnderCallArg(const BinaryOperator *MulBO,
                                const Expr *Root,
                                CheckerContext &C);
  static bool isMulUnderArrayIndex(const BinaryOperator *MulBO,
                                   CheckerContext &C);

  // CFI-style erase region math: ((X >> k) & ~((1<<K)-1)) * interleave
  static bool isConstMaskClearingLowBits(const Expr *E, unsigned &ClearedBits,
                                         CheckerContext &C);
  static bool matchMaskedShiftExpr(const Expr *E, unsigned &ShiftAmt,
                                   unsigned &ClearedBits, CheckerContext &C);
  static bool isBenignCFIMaskedShiftInterleaveCase(const BinaryOperator *MulBO,
                                                   CheckerContext &C);

  // Aggregated FP gate.
  static bool isFalsePositive(const Expr *Root,
                              const BinaryOperator *MulBO,
                              const Expr *LHSExpr,
                              CheckerContext &C);

  static void clampByNameHints(const Expr *E, llvm::APInt &Min, llvm::APInt &Max,
                               CheckerContext &C);

  void emitReport(const BinaryOperator *MulBO, QualType LHSType,
                  CheckerContext &C) const;
};

// Return bit width of a type.
unsigned SAGenTestChecker::getTypeBitWidth(QualType QT, CheckerContext &C) {
  return C.getASTContext().getTypeSize(QT);
}

// Check for integer-like types (integers and enums), ignoring typedefs/quals.
bool SAGenTestChecker::isIntegerLike(QualType QT) {
  QT = QT.getCanonicalType();
  return QT->isIntegerType() || QT->isEnumeralType();
}

// Wide target: unsigned integer-like and width >= 64 bits (covers u64, dma_addr_t on 64-bit).
// Narrowing to unsigned eliminates benign signed long "size" temporaries like ALSA's private_size.
bool SAGenTestChecker::isWideTargetType(QualType QT, CheckerContext &C) {
  if (!isIntegerLike(QT))
    return false;

  if (!QT->isUnsignedIntegerOrEnumerationType())
    return false;

  unsigned Bits = getTypeBitWidth(QT, C);
  return Bits >= 64;
}

// Try to fold expression to constant integer. If succeeds, skip reporting.
bool SAGenTestChecker::isConstantFolded(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt EvalRes;
  return EvaluateExprToInt(EvalRes, E, C);
}

// Compute min and max representable by a type in 128-bit APInt.
void SAGenTestChecker::getTypeRange128(QualType QT, CheckerContext &C,
                                       llvm::APInt &Min, llvm::APInt &Max) {
  unsigned Bits = getTypeBitWidth(QT, C);
  bool IsUnsigned = QT->isUnsignedIntegerOrEnumerationType();
  if (IsUnsigned) {
    llvm::APInt TMin(Bits, 0, /*isSigned=*/false);
    llvm::APInt TMax = llvm::APInt::getMaxValue(Bits);
    Min = TMin.zextOrTrunc(128);
    Max = TMax.zextOrTrunc(128);
  } else {
    llvm::APInt TMin = llvm::APInt::getSignedMinValue(Bits);
    llvm::APInt TMax = llvm::APInt::getSignedMaxValue(Bits);
    Min = TMin.sextOrTrunc(128);
    Max = TMax.sextOrTrunc(128);
  }
}

// Clamp ranges based on identifier hints (heuristics for kernel).
void SAGenTestChecker::clampByNameHints(const Expr *E, llvm::APInt &Min, llvm::APInt &Max,
                                        CheckerContext &C) {
  // Small interleave factors in flash CFI stacks are common (1,2,4,8,...).
  if (exprNameContains(E, {"interleave"}, C)) {
    llvm::APInt One = llvm::APInt(128, 1, /*isSigned*/false);
    llvm::APInt Up = llvm::APInt(128, 64, /*isSigned*/false);
    if (Min.slt(One)) Min = One;
    if (Max.sgt(Up))  Max = Up;
  }
}

// Lightweight interval analysis for expressions. Always returns true,
// providing a conservative range, falling back to type-based ranges.
// Depth-limited to avoid pathological recursion.
bool SAGenTestChecker::getExprRange128(const Expr *E, CheckerContext &C,
                                       llvm::APInt &Min, llvm::APInt &Max,
                                       unsigned Depth) {
  const unsigned MaxDepth = 8;
  if (!E || Depth > MaxDepth) {
    getTypeRange128(E ? E->getType() : C.getASTContext().IntTy, C, Min, Max);
    return true;
  }

  // If this expression folds to a constant, use that precise value.
  llvm::APSInt Folded;
  if (EvaluateExprToInt(Folded, E->IgnoreParenImpCasts(), C)) {
    llvm::APInt V = Folded.extOrTrunc(128);
    Min = V;
    Max = V;
    return true;
  }

  // Parens: skip
  if (const auto *PE = dyn_cast<ParenExpr>(E)) {
    return getExprRange128(PE->getSubExpr(), C, Min, Max, Depth + 1);
  }

  // Casts: get sub-range and clamp to destination type.
  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    llvm::APInt SMin(128, 0), SMax(128, 0);
    (void)getExprRange128(CE->getSubExpr(), C, SMin, SMax, Depth + 1);
    llvm::APInt TMin(128, 0), TMax(128, 0);
    getTypeRange128(CE->getType(), C, TMin, TMax);
    // Intersect [SMin, SMax] with [TMin, TMax].
    Min = SMin;
    Max = SMax;
    if (Min.slt(TMin)) Min = TMin;
    if (Max.sgt(TMax)) Max = TMax;
    if (Min.sgt(Max)) { Min = TMin; Max = TMax; }
    return true;
  }

  // Integer literal
  if (const auto *IL = dyn_cast<IntegerLiteral>(E->IgnoreParenCasts())) {
    llvm::APInt V = IL->getValue();
    V = V.sextOrTrunc(128);
    Min = V;
    Max = V;
    return true;
  }

  // Character literal
  if (const auto *CL = dyn_cast<CharacterLiteral>(E->IgnoreParenCasts())) {
    uint64_t V = static_cast<uint64_t>(CL->getValue());
    llvm::APInt A(128, V, /*isSigned=*/false);
    Min = A;
    Max = A;
    return true;
  }

  // Unary operator handling
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    UnaryOperatorKind K = UO->getOpcode();
    if (K == UO_Plus) {
      return getExprRange128(UO->getSubExpr(), C, Min, Max, Depth + 1);
    }
    if (K == UO_Minus) {
      llvm::APInt SMin(128, 0), SMax(128, 0);
      (void)getExprRange128(UO->getSubExpr(), C, SMin, SMax, Depth + 1);
      // Negate reverses bounds: [-b, -a]
      Min = -SMax;
      Max = -SMin;
      return true;
    }
    // Bitwise not may be folded above; otherwise fallback.
    if (K == UO_Not) {
      getTypeRange128(UO->getType(), C, Min, Max);
      return true;
    }
    // Address/deref or other: fallback to type range
    getTypeRange128(UO->getType(), C, Min, Max);
    return true;
  }

  // Binary operators
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperatorKind Op = BO->getOpcode();

    // RHS path for comma
    if (Op == BO_Comma) {
      return getExprRange128(BO->getRHS(), C, Min, Max, Depth + 1);
    }

    // Assign: resulting value is RHS
    if (Op == BO_Assign) {
      return getExprRange128(BO->getRHS(), C, Min, Max, Depth + 1);
    }

    llvm::APInt LMin(128, 0), LMax(128, 0), RMin(128, 0), RMax(128, 0);
    (void)getExprRange128(BO->getLHS(), C, LMin, LMax, Depth + 1);
    (void)getExprRange128(BO->getRHS(), C, RMin, RMax, Depth + 1);

    switch (Op) {
    case BO_Add: {
      Min = LMin + RMin;
      Max = LMax + RMax;
      return true;
    }
    case BO_Sub: {
      Min = LMin - RMax;
      Max = LMax - RMin;
      return true;
    }
    case BO_Mul: {
      // Conservative: range of product = hull of endpoints.
      llvm::APInt Cands[4] = { LMin * RMin, LMin * RMax, LMax * RMin, LMax * RMax };
      Min = Cands[0];
      Max = Cands[0];
      for (int i = 1; i < 4; ++i) {
        if (Cands[i].slt(Min)) Min = Cands[i];
        if (Cands[i].sgt(Max)) Max = Cands[i];
      }
      return true;
    }
    case BO_Shr: {
      // If RHS is a constant, tighten by shifting bounds; valid for nonnegative ranges.
      llvm::APSInt AmtAPS;
      if (EvaluateExprToInt(AmtAPS, BO->getRHS()->IgnoreParenImpCasts(), C)) {
        unsigned Amt = (unsigned)AmtAPS.getExtValue();
        // If LHS min is nonnegative (common for unsigned types), shift both.
        if (!LMin.isNegative() && !LMax.isNegative()) {
          Min = LMin.lshr(Amt);
          Max = LMax.lshr(Amt);
          return true;
        }
      }
      getTypeRange128(BO->getType(), C, Min, Max);
      return true;
    }
    case BO_Shl: {
      llvm::APSInt AmtAPS;
      if (EvaluateExprToInt(AmtAPS, BO->getRHS()->IgnoreParenImpCasts(), C)) {
        unsigned Amt = (unsigned)AmtAPS.getExtValue();
        if (!LMin.isNegative() && !LMax.isNegative()) {
          Min = LMin.shl(Amt);
          Max = LMax.shl(Amt);
          return true;
        }
      }
      getTypeRange128(BO->getType(), C, Min, Max);
      return true;
    }
    case BO_And: {
      // If one side is a constant mask M, result is within [0, min(OtherMax, M)].
      llvm::APSInt ConstAPS;
      bool LConst = EvaluateExprToInt(ConstAPS, BO->getLHS()->IgnoreParenImpCasts(), C);
      if (LConst) {
        llvm::APInt M = ConstAPS.extOrTrunc(128);
        llvm::APInt Zero(128, 0, false);
        Min = Zero;
        Max = (LMax.slt(M)) ? LMax : M;
        clampByNameHints(BO->getRHS(), Min, Max, C);
        return true;
      }
      bool RConst = EvaluateExprToInt(ConstAPS, BO->getRHS()->IgnoreParenImpCasts(), C);
      if (RConst) {
        llvm::APInt M = ConstAPS.extOrTrunc(128);
        llvm::APInt Zero(128, 0, false);
        Min = Zero;
        Max = (RMax.slt(M)) ? RMax : M;
        clampByNameHints(BO->getLHS(), Min, Max, C);
        return true;
      }
      getTypeRange128(BO->getType(), C, Min, Max);
      return true;
    }
    case BO_Or:
    case BO_Xor:
    default:
      // Fallback for complex ops
      getTypeRange128(BO->getType(), C, Min, Max);
      return true;
    }
  }

  // Conditional operator ?:
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    llvm::APInt TMin(128, 0), TMax(128, 0), FMin(128, 0), FMax(128, 0);
    (void)getExprRange128(CO->getTrueExpr(), C, TMin, TMax, Depth + 1);
    (void)getExprRange128(CO->getFalseExpr(), C, FMin, FMax, Depth + 1);
    Min = TMin.slt(FMin) ? TMin : FMin;
    Max = TMax.sgt(FMax) ? TMax : FMax;
    return true;
  }

  // Array subscripts: use element type range.
  if (isa<ArraySubscriptExpr>(E)) {
    getTypeRange128(E->getType(), C, Min, Max);
    return true;
  }

  // Member access / decl ref: use their type ranges, then clamp by name hints.
  if (isa<MemberExpr>(E) || isa<DeclRefExpr>(E)) {
    getTypeRange128(E->getType(), C, Min, Max);
    clampByNameHints(E, Min, Max, C);
    return true;
  }

  // CallExpr or anything else: fallback to type-based range.
  getTypeRange128(E->getType(), C, Min, Max);
  return true;
}

// If we can bound both operands, compute the product interval and verify it fits
// entirely in the multiplication's result type. No non-negativity requirement.
bool SAGenTestChecker::productDefinitelyFitsInType(const Expr *L, const Expr *R,
                                                   QualType MulType, CheckerContext &C) {
  llvm::APInt LMin(128, 0), LMax(128, 0), RMin(128, 0), RMax(128, 0);
  (void)getExprRange128(L, C, LMin, LMax);
  (void)getExprRange128(R, C, RMin, RMax);

  // Compute product bounds (signed).
  llvm::APInt Cands[4] = { LMin * RMin, LMin * RMax, LMax * RMin, LMax * RMax };
  llvm::APInt PMin = Cands[0];
  llvm::APInt PMax = Cands[0];
  for (int i = 1; i < 4; ++i) {
    if (Cands[i].slt(PMin)) PMin = Cands[i];
    if (Cands[i].sgt(PMax)) PMax = Cands[i];
  }

  // MulType range.
  llvm::APInt TMin(128, 0), TMax(128, 0);
  getTypeRange128(MulType, C, TMin, TMax);

  // Product definitely fits if entire [PMin, PMax] within [TMin, TMax].
  if (PMin.sge(TMin) && PMax.sle(TMax))
    return true;

  return false;
}

// Restrict traversal to the value-producing path of Root.
bool SAGenTestChecker::findFirstSuspiciousMulOnValuePath(const Expr *Root,
                                                         unsigned TargetBits,
                                                         const BinaryOperator *&OutMul,
                                                         CheckerContext &C) {
  if (!Root)
    return false;

  const Expr *E = Root->IgnoreParenImpCasts();

  // Handle binary operators explicitly.
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperatorKind Op = BO->getOpcode();

    if (Op == BO_Mul) {
      QualType ResT = BO->getType();
      if (isIntegerLike(ResT)) {
        unsigned MulBits = getTypeBitWidth(ResT, C);
        if (MulBits < TargetBits) {
          // Guard: if we can prove the product cannot overflow in ResT, skip.
          if (!productDefinitelyFitsInType(BO->getLHS(), BO->getRHS(), ResT, C)) {
            OutMul = BO;
            return true;
          }
        }
      }
      // Continue searching sub-expressions.
      if (findFirstSuspiciousMulOnValuePath(BO->getLHS(), TargetBits, OutMul, C))
        return true;
      if (findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C))
        return true;
      return false;
    }

    // For comma operator, only the RHS contributes to the resulting value.
    if (Op == BO_Comma) {
      return findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C);
    }

    // For simple assignment in a subexpression, only RHS determines resulting value.
    if (Op == BO_Assign) {
      return findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C);
    }

    // For other arithmetic/bitwise operators, both sides contribute to value.
    if (findFirstSuspiciousMulOnValuePath(BO->getLHS(), TargetBits, OutMul, C))
      return true;
    if (findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C))
      return true;
    return false;
  }

  // Conditional operator: either arm may be the resulting value.
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    if (findFirstSuspiciousMulOnValuePath(CO->getTrueExpr(), TargetBits, OutMul, C))
      return true;
    if (findFirstSuspiciousMulOnValuePath(CO->getFalseExpr(), TargetBits, OutMul, C))
      return true;
    return false;
  }

  // Unary operator: break on address/indirection which form lvalue/address computation.
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    UnaryOperatorKind UOK = UO->getOpcode();
    if (UOK == UO_AddrOf || UOK == UO_Deref)
      return false;
    return findFirstSuspiciousMulOnValuePath(UO->getSubExpr(), TargetBits, OutMul, C);
  }

  // Explicit casts: continue through.
  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    return findFirstSuspiciousMulOnValuePath(CE->getSubExpr(), TargetBits, OutMul, C);
  }

  // Do not traverse into call arguments: call's return value is the value path.
  if (isa<CallExpr>(E))
    return false;

  // Array subscripts: indexing/math does not become the resulting rvalue itself.
  if (isa<ArraySubscriptExpr>(E))
    return false;

  // Member access: base computation does not propagate to the value itself.
  if (isa<MemberExpr>(E))
    return false;

  // Default: stop if leaf or non-handled node on value path.
  return false;
}

// Extract identifier-like name from an expression (variable or field), else empty.
std::string SAGenTestChecker::extractIdentifierLikeName(const Expr *E) {
  if (!E)
    return {};
  E = E->IgnoreParenImpCasts();

  // Look through deref to get the underlying identifier.
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref || UO->getOpcode() == UO_AddrOf)
      return extractIdentifierLikeName(UO->getSubExpr());
  }

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
      return FD->getNameAsString();
  }
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
      return ND->getNameAsString();
  }
  return {};
}

bool SAGenTestChecker::nameContains(StringRef TextLower,
                                    std::initializer_list<StringRef> Needles) {
  for (StringRef N : Needles) {
    if (TextLower.contains(N))
      return true;
  }
  return false;
}

// Address/size-like LHS filter for intended bug surface (narrowed).
// Focus on addr/size/pitch/stride-like sinks. Avoid generic "len", "offset" to reduce FPs.
bool SAGenTestChecker::isAddressOrSizeLikeLHS(const Expr *LHS) {
  std::string Name = extractIdentifierLikeName(LHS);
  if (Name.empty())
    return false;
  std::string Lower = Name;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);

  // Heuristic keywords that map to memory/byte/size/address semantics.
  return nameContains(Lower,
                      {"addr", "address", "dma_addr",
                       "size", "bytes", "nbytes",
                       "pitch", "stride"});
}

// IRQ-like context suppression.
bool SAGenTestChecker::isIrqLikeContext(const Expr *Root, const Expr *LHS, CheckerContext &C) {
  // LHS name contains irq-ish patterns (e.g., out_hwirq).
  std::string LHSName = extractIdentifierLikeName(LHS);
  std::string Lower = LHSName;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
  if (!Lower.empty() && nameContains(Lower, {"irq", "hwirq", "intid", "gsi", "spi", "ppi"}))
    return true;

  // Function name contains irq-domain style names (e.g., *_irq_domain_*xlate*).
  const FunctionDecl *FD = nullptr;
  if (const auto *LC = C.getLocationContext())
    FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (FD) {
    std::string FName = FD->getNameAsString();
    std::transform(FName.begin(), FName.end(), FName.begin(), ::tolower);
    if (nameContains(FName, {"irq", "hwirq", "xlate", "irq_domain"}))
      return true;
  }

  // Source expression text heuristic.
  if (ExprHasName(Root, "jiffies", C) || ExprHasName(Root, "irq", C) ||
      ExprHasName(Root, "hwirq", C))
    return true;

  return false;
}

// Returns true if expression is of the form (1 << X) or (1U << X).
bool SAGenTestChecker::isShiftOfOne(const Expr *E) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Shl)
    return false;
  const auto *LHS_IL = dyn_cast<IntegerLiteral>(BO->getLHS()->IgnoreParenCasts());
  if (!LHS_IL) return false;
  return LHS_IL->getValue() == 1;
}

bool SAGenTestChecker::exprNameContains(const Expr *E,
                                        std::initializer_list<StringRef> Needles,
                                        CheckerContext &C) {
  if (!E) return false;
  // Try identifier name first.
  std::string Name = extractIdentifierLikeName(E);
  std::string Lower = Name;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
  if (!Lower.empty() && nameContains(Lower, Needles))
    return true;
  // Fallback to source text.
  for (StringRef N : Needles) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

// block-size-like: variable named block_size/blksize/bsize/fs_block_size
// OR an expression like (1 << block_bits) or (1U << blkbits)
bool SAGenTestChecker::isBlockSizeLikeExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  if (exprNameContains(E, {"block_size", "blksize", "bsize", "fs_block_size",
                           "page_size", "blocksize"}, C))
    return true;
  if (isShiftOfOne(E))
    return true;
  // Also accept (1 << something) nested within parens/casts.
  return false;
}

// recursively check if E is a +/- chain composed of names from Needles and integer literals
bool SAGenTestChecker::isAddSubChainRec(const Expr *E,
                                        std::initializer_list<StringRef> Needles,
                                        CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (isa<IntegerLiteral>(E))
    return true;
  if (exprNameContains(E, Needles, C))
    return true;
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add || BO->getOpcode() == BO_Sub) {
      return isAddSubChainRec(BO->getLHS(), Needles, C) &&
             isAddSubChainRec(BO->getRHS(), Needles, C);
    }
  }
  return false;
}

// count-like: combinations like (last - i + 1), (nr_blks), (blocks), etc.
bool SAGenTestChecker::isAddSubChainOfNames(const Expr *E,
                                            std::initializer_list<StringRef> Needles,
                                            CheckerContext &C) {
  return isAddSubChainRec(E, Needles, C);
}

bool SAGenTestChecker::isBlockCountLikeExpr(const Expr *E, CheckerContext &C) {
  // Common identifiers in block/folio counting contexts.
  return isAddSubChainOfNames(
      E,
      {"first", "last", "end", "i", "j", "k", "count", "nr", "nr_blks",
       "nr_blocks", "blocks", "blks", "nblocks", "nblks", "block"},
      C);
}

// Identify iomap/folio/page context from function name or expression text.
bool SAGenTestChecker::isPageOrFolioContext(const Expr *Root, CheckerContext &C) {
  const FunctionDecl *FD = nullptr;
  if (const auto *LC = C.getLocationContext())
    FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (FD) {
    std::string FName = FD->getNameAsString();
    std::transform(FName.begin(), FName.end(), FName.begin(), ::tolower);
    if (nameContains(FName, {"iomap", "folio", "readahead", "readpage"}))
      return true;
  }
  // Fallback to textual hints.
  if (ExprHasName(Root, "folio", C) || ExprHasName(Root, "iomap", C) ||
      ExprHasName(Root, "page", C))
    return true;
  return false;
}

// Secondary guard: filter known benign contexts to avoid false positives.
bool SAGenTestChecker::isFalsePositiveContext(const Expr *Root,
                                              const BinaryOperator *MulBO,
                                              const Expr *LHSExpr,
                                              CheckerContext &C) {
  (void)MulBO;

  // 1) Time arithmetic.
  if (ExprHasName(Root, "jiffies", C))
    return true;

  // 2) Timeout-like LHS names.
  const CompoundAssignOperator *CAO =
      findSpecificTypeInParents<CompoundAssignOperator>(Root, C);
  const BinaryOperator *AssignBO =
      findSpecificTypeInParents<BinaryOperator>(Root, C);

  const Expr *LHS = LHSExpr;
  if (!LHS) {
    if (CAO)
      LHS = CAO->getLHS();
    else if (AssignBO && AssignBO->getOpcode() == BO_Assign)
      LHS = AssignBO->getLHS();
  }

  if (LHS) {
    std::string LHSName = extractIdentifierLikeName(LHS);
    if (!LHSName.empty()) {
      std::string Lower = LHSName;
      std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
      if (nameContains(Lower, {"expire", "expiry", "timeout", "deadline", "jiffies"}))
        return true;
    }
  }

  // 3) IRQ-like contexts.
  if (LHS && isIrqLikeContext(Root, LHS, C))
    return true;

  // 4) Kernel iomap/folio math: count-like * block-size-like, in page/folio context.
  if (MulBO && isPageOrFolioContext(Root, C)) {
    const Expr *ML = MulBO->getLHS()->IgnoreParenImpCasts();
    const Expr *MR = MulBO->getRHS()->IgnoreParenImpCasts();
    bool IsBlockGeom =
        (isBlockSizeLikeExpr(ML, C) && isBlockCountLikeExpr(MR, C)) ||
        (isBlockSizeLikeExpr(MR, C) && isBlockCountLikeExpr(ML, C));
    if (IsBlockGeom)
      return true;
  }

  return false;
}

// Return true if the '*' is nested under a CallExpr (i.e., used as a call argument)
// relative to the current assignment/addition root.
bool SAGenTestChecker::isMulUnderCallArg(const BinaryOperator *MulBO,
                                         const Expr *Root,
                                         CheckerContext &C) {
  (void)Root;
  const CallExpr *CE = findSpecificTypeInParents<CallExpr>(MulBO, C);
  return CE != nullptr;
}

// Return true if '*' is used solely as part of an ArraySubscriptExpr (index).
bool SAGenTestChecker::isMulUnderArrayIndex(const BinaryOperator *MulBO,
                                            CheckerContext &C) {
  const ArraySubscriptExpr *ASE = findSpecificTypeInParents<ArraySubscriptExpr>(MulBO, C);
  return ASE != nullptr;
}

// Detect E is a constant mask that clears at least K low bits: e.g., ~0xff or 0xffff0000.
bool SAGenTestChecker::isConstMaskClearingLowBits(const Expr *E, unsigned &ClearedBits,
                                                  CheckerContext &C) {
  llvm::APSInt APS;
  if (!EvaluateExprToInt(APS, E->IgnoreParenImpCasts(), C))
    return false;
  llvm::APInt V = APS.extOrTrunc(128);
  // Number of trailing zero bits gives cleared low bits by this mask.
  unsigned TZ = V.countTrailingZeros();
  if (TZ == 0)
    return false;
  ClearedBits = TZ;
  return true;
}

// Detect ((X >> ShiftAmt) & MaskClearingLowClearedBits)
bool SAGenTestChecker::matchMaskedShiftExpr(const Expr *E, unsigned &ShiftAmt,
                                            unsigned &ClearedBits, CheckerContext &C) {
  E = E ? E->IgnoreParenImpCasts() : nullptr;
  const auto *AndBO = dyn_cast_or_null<BinaryOperator>(E);
  if (!AndBO || AndBO->getOpcode() != BO_And)
    return false;

  // AND is commutative: check both sides for the mask and the shift.
  auto TryMatch = [&](const Expr *Left, const Expr *Right) -> bool {
    Left = Left ? Left->IgnoreParenImpCasts() : nullptr;
    Right = Right ? Right->IgnoreParenImpCasts() : nullptr;
    unsigned K = 0;
    if (!isConstMaskClearingLowBits(Right, K, C))
      return false;
    const auto *ShrBO = dyn_cast<BinaryOperator>(Left);
    if (!ShrBO || ShrBO->getOpcode() != BO_Shr)
      return false;
    llvm::APSInt AmtAPS;
    if (!EvaluateExprToInt(AmtAPS, ShrBO->getRHS()->IgnoreParenImpCasts(), C))
      return false;
    int64_t SA = AmtAPS.getExtValue();
    if (SA < 0)
      return false;
    ShiftAmt = (unsigned)SA;
    ClearedBits = K;
    return true;
  };

  if (TryMatch(AndBO->getLHS(), AndBO->getRHS()))
    return true;
  if (TryMatch(AndBO->getRHS(), AndBO->getLHS()))
    return true;
  return false;
}

// Specific benign CFI case: ((X >> k) & mask-clearing >=8 low bits) * <interleave>
bool SAGenTestChecker::isBenignCFIMaskedShiftInterleaveCase(const BinaryOperator *MulBO,
                                                            CheckerContext &C) {
  if (!MulBO || MulBO->getOpcode() != BO_Mul)
    return false;
  const Expr *L = MulBO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = MulBO->getRHS()->IgnoreParenImpCasts();

  unsigned ShiftAmt = 0, Cleared = 0;
  // One side must be masked-shift; the other named "interleave".
  bool LMasked = matchMaskedShiftExpr(L, ShiftAmt, Cleared, C);
  bool RMasked = matchMaskedShiftExpr(R, ShiftAmt, Cleared, C);
  if (!LMasked && !RMasked)
    return false;

  const Expr *Other = LMasked ? R : L;
  if (!exprNameContains(Other, {"interleave"}, C))
    return false;

  // Require that at least 8 low bits are cleared, as in (~0xff) pattern.
  if (Cleared < 8)
    return false;

  return true;
}

// Aggregated FP logic.
bool SAGenTestChecker::isFalsePositive(const Expr *Root,
                                       const BinaryOperator *MulBO,
                                       const Expr *LHSExpr,
                                       CheckerContext &C) {
  if (!MulBO)
    return true;

  // Suppress when LHS is not address/size-like (we target addr/size/pitch/stride).
  if (!isAddressOrSizeLikeLHS(LHSExpr))
    return true;

  // Suppress known benign contexts.
  if (isFalsePositiveContext(Root, MulBO, LHSExpr, C))
    return true;

  // Suppress when '*' is under a call arg or an array index.
  if (isMulUnderCallArg(MulBO, Root, C))
    return true;
  if (isMulUnderArrayIndex(MulBO, C))
    return true;

  // Targeted suppression: CFI erase-region product pattern.
  if (isBenignCFIMaskedShiftInterleaveCase(MulBO, C))
    return true;

  return false;
}

void SAGenTestChecker::emitReport(const BinaryOperator *MulBO, QualType LHSType,
                                  CheckerContext &C) const {
  if (!MulBO)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  llvm::SmallString<128> Msg;
  Msg += "Multiplication occurs in a narrower type and is widened after; ";
  Msg += "possible overflow before assignment/addition to wide type";
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(MulBO->getSourceRange());
  C.emitReport(std::move(R));
}

// Handle assignments and compound assignments that bind values to wide targets.
void SAGenTestChecker::checkBind(SVal, SVal, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // Prefer detecting compound assignments first (e.g., +=)
  if (const auto *CAO = findSpecificTypeInParents<CompoundAssignOperator>(S, C)) {
    BinaryOperatorKind Op = CAO->getOpcode();
    // We care about adding/subtracting a product into a wide accumulator.
    if (Op == BO_AddAssign || Op == BO_SubAssign) {
      const Expr *LHS = CAO->getLHS()->IgnoreParenImpCasts();
      if (!LHS)
        return;
      QualType LT = LHS->getType();
      if (!isWideTargetType(LT, C))
        return;

      const BinaryOperator *MulBO = nullptr;
      const Expr *RHS = CAO->getRHS();
      if (findFirstSuspiciousMulOnValuePath(RHS, getTypeBitWidth(LT, C), MulBO, C)) {
        // Extra safety: if multiplication definitely fits in its own type, skip.
        if (MulBO && productDefinitelyFitsInType(MulBO->getLHS(), MulBO->getRHS(),
                                                 MulBO->getType(), C)) {
          return;
        }
        if (MulBO && !isConstantFolded(MulBO, C) &&
            !isFalsePositive(RHS, MulBO, LHS, C)) {
          emitReport(MulBO, LT, C);
        }
      }
    }
    return;
  }

  // Handle simple assignments: T_wide lhs = <expr with mul>;
  if (const auto *BO = findSpecificTypeInParents<BinaryOperator>(S, C)) {
    if (BO->getOpcode() != BO_Assign)
      return;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    if (!LHS)
      return;
    QualType LT = LHS->getType();
    if (!isWideTargetType(LT, C))
      return;

    const Expr *RHS = BO->getRHS();
    const BinaryOperator *MulBO = nullptr;
    if (findFirstSuspiciousMulOnValuePath(RHS, getTypeBitWidth(LT, C), MulBO, C)) {
      if (MulBO && productDefinitelyFitsInType(MulBO->getLHS(), MulBO->getRHS(),
                                               MulBO->getType(), C)) {
        return;
      }
      if (MulBO && !isConstantFolded(MulBO, C) &&
          !isFalsePositive(RHS, MulBO, LHS, C)) {
        emitReport(MulBO, LT, C);
      }
    }
  }
}

// Handle variable initializations: wide_var = <expr with mul>;
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->hasInit())
      continue;

    QualType T = VD->getType();
    if (!isWideTargetType(T, C))
      continue;

    const Expr *Init = VD->getInit();
    const BinaryOperator *MulBO = nullptr;
    if (findFirstSuspiciousMulOnValuePath(Init, getTypeBitWidth(T, C), MulBO, C)) {
      // For initialization, ensure the variable name is address/size-like.
      std::string Name = VD->getNameAsString();
      std::string Lower = Name;
      std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
      bool IsAddrSizeLike =
          nameContains(Lower,
                       {"addr", "address", "dma_addr",
                        "size", "bytes", "nbytes",
                        "pitch", "stride"});
      if (!IsAddrSizeLike)
        continue;

      if (MulBO && productDefinitelyFitsInType(MulBO->getLHS(), MulBO->getRHS(),
                                               MulBO->getType(), C)) {
        continue;
      }

      if (MulBO && !isConstantFolded(MulBO, C) &&
          !isFalsePositive(Init, MulBO, nullptr, C)) {
        emitReport(MulBO, T, C);
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow or mixed-width multiplication that may overflow before being assigned/added to a wide integer",
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
