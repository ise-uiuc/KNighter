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

File:| drivers/crypto/intel/qat/qat_common/qat_uclo.c
---|---
Warning:| line 652, column 3
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


32    |  if (encap_image->img_ptr) {
33    | 		ae_slice->ctx_mask_assigned =
34    | 					encap_image->img_ptr->ctx_assigned;
35    | 		ae_data->eff_ustore_size = obj_handle->ustore_phy_size;
36    | 	} else {
37    | 		ae_slice->ctx_mask_assigned = 0;
38    | 	}
39    | 	ae_slice->region = kzalloc(sizeof(*ae_slice->region), GFP_KERNEL);
40    |  if (!ae_slice->region)
41    |  return -ENOMEM;
42    | 	ae_slice->page = kzalloc(sizeof(*ae_slice->page), GFP_KERNEL);
43    |  if (!ae_slice->page)
44    |  goto out_err;
45    | 	page = ae_slice->page;
46    | 	page->encap_page = encap_image->page;
47    | 	ae_slice->page->region = ae_slice->region;
48    | 	ae_data->slice_num++;
49    |  return 0;
50    | out_err:
51    | 	kfree(ae_slice->region);
52    | 	ae_slice->region = NULL;
53    |  return -ENOMEM;
54    | }
55    |
56    | static int qat_uclo_free_ae_data(struct icp_qat_uclo_aedata *ae_data)
57    | {
58    |  unsigned int i;
59    |
60    |  if (!ae_data) {
61    |  pr_err("QAT: bad argument, ae_data is NULL\n ");
62    |  return -EINVAL;
63    | 	}
64    |
65    |  for (i = 0; i < ae_data->slice_num; i++) {
66    | 		kfree(ae_data->ae_slices[i].region);
67    | 		ae_data->ae_slices[i].region = NULL;
68    | 		kfree(ae_data->ae_slices[i].page);
69    | 		ae_data->ae_slices[i].page = NULL;
70    | 	}
71    |  return 0;
72    | }
73    |
74    | static char *qat_uclo_get_string(struct icp_qat_uof_strtable *str_table,
75    |  unsigned int str_offset)
76    | {
77    |  if (!str_table->table_len || str_offset > str_table->table_len)
78    |  return NULL;
79    |  return (char *)(((uintptr_t)(str_table->strings)) + str_offset);
80    | }
81    |
82    | static int qat_uclo_check_uof_format(struct icp_qat_uof_filehdr *hdr)
83    | {
84    |  int maj = hdr->maj_ver & 0xff;
85    |  int min = hdr->min_ver & 0xff;
86    |
87    |  if (hdr->file_id != ICP_QAT_UOF_FID) {
88    |  pr_err("QAT: Invalid header 0x%x\n", hdr->file_id);
89    |  return -EINVAL;
90    | 	}
91    |  if (min != ICP_QAT_UOF_MINVER || maj != ICP_QAT_UOF_MAJVER) {
92    |  pr_err("QAT: bad UOF version, major 0x%x, minor 0x%x\n",
93    |  maj, min);
94    |  return -EINVAL;
95    | 	}
96    |  return 0;
97    | }
98    |
99    | static int qat_uclo_check_suof_format(struct icp_qat_suof_filehdr *suof_hdr)
100   | {
101   |  int maj = suof_hdr->maj_ver & 0xff;
102   |  int min = suof_hdr->min_ver & 0xff;
103   |
104   |  if (suof_hdr->file_id != ICP_QAT_SUOF_FID) {
105   |  pr_err("QAT: invalid header 0x%x\n", suof_hdr->file_id);
106   |  return -EINVAL;
107   | 	}
108   |  if (suof_hdr->fw_type != 0) {
109   |  pr_err("QAT: unsupported firmware type\n");
110   |  return -EINVAL;
111   | 	}
112   |  if (suof_hdr->num_chunks <= 0x1) {
113   |  pr_err("QAT: SUOF chunk amount is incorrect\n");
114   |  return -EINVAL;
115   | 	}
116   |  if (maj != ICP_QAT_SUOF_MAJVER || min != ICP_QAT_SUOF_MINVER) {
117   |  pr_err("QAT: bad SUOF version, major 0x%x, minor 0x%x\n",
118   |  maj, min);
119   |  return -EINVAL;
120   | 	}
121   |  return 0;
122   | }
123   |
124   | static void qat_uclo_wr_sram_by_words(struct icp_qat_fw_loader_handle *handle,
125   |  unsigned int addr, unsigned int *val,
126   |  unsigned int num_in_bytes)
397   |
398   | 		ustore_size = obj_handle->ae_data[ae].eff_ustore_size;
399   | 		patt_pos = page->beg_addr_p + page->micro_words_num;
400   |
401   | 		qat_hal_wr_uwords(handle, (unsigned char)ae, 0,
402   | 				  page->beg_addr_p, &fill_data[0]);
403   | 		qat_hal_wr_uwords(handle, (unsigned char)ae, patt_pos,
404   | 				  ustore_size - patt_pos + 1,
405   | 				  &fill_data[page->beg_addr_p]);
406   | 	}
407   | 	kfree(fill_data);
408   |  return 0;
409   | }
410   |
411   | static int qat_uclo_init_memory(struct icp_qat_fw_loader_handle *handle)
412   | {
413   |  int i, ae;
414   |  struct icp_qat_uclo_objhandle *obj_handle = handle->obj_handle;
415   |  struct icp_qat_uof_initmem *initmem = obj_handle->init_mem_tab.init_mem;
416   |  unsigned long ae_mask = handle->hal_handle->ae_mask;
417   |
418   |  for (i = 0; i < obj_handle->init_mem_tab.entry_num; i++) {
419   |  if (initmem->num_in_bytes) {
420   |  if (qat_uclo_init_ae_memory(handle, initmem))
421   |  return -EINVAL;
422   | 		}
423   | 		initmem = (struct icp_qat_uof_initmem *)((uintptr_t)(
424   | 			(uintptr_t)initmem +
425   |  sizeof(struct icp_qat_uof_initmem)) +
426   | 			(sizeof(struct icp_qat_uof_memvar_attr) *
427   | 			initmem->val_attr_num));
428   | 	}
429   |
430   |  for_each_set_bit(ae, &ae_mask, handle->hal_handle->ae_max_num) {
431   |  if (qat_hal_batch_wr_lm(handle, ae,
432   | 					obj_handle->lm_init_tab[ae])) {
433   |  pr_err("QAT: fail to batch init lmem for AE %d\n", ae);
434   |  return -EINVAL;
435   | 		}
436   | 		qat_uclo_cleanup_batch_init_list(handle,
437   | 						 &obj_handle->lm_init_tab[ae]);
438   | 		qat_uclo_batch_wr_umem(handle, ae,
439   | 				       obj_handle->umem_init_tab[ae]);
440   | 		qat_uclo_cleanup_batch_init_list(handle,
441   | 						 &obj_handle->
442   | 						 umem_init_tab[ae]);
443   | 	}
444   |  return 0;
445   | }
446   |
447   | static void *qat_uclo_find_chunk(struct icp_qat_uof_objhdr *obj_hdr,
448   |  char *chunk_id, void *cur)
449   | {
450   |  int i;
451   |  struct icp_qat_uof_chunkhdr *chunk_hdr =
452   | 	    (struct icp_qat_uof_chunkhdr *)
453   | 	    ((uintptr_t)obj_hdr + sizeof(struct icp_qat_uof_objhdr));
454   |
455   |  for (i = 0; i < obj_hdr->num_chunks; i++) {
456   |  if ((cur < (void *)&chunk_hdr[i]) &&
457   | 		    !strncmp(chunk_hdr[i].chunk_id, chunk_id,
458   |  ICP_QAT_UOF_OBJID_LEN)) {
459   |  return &chunk_hdr[i];
460   | 		}
461   | 	}
462   |  return NULL;
463   | }
464   |
465   | static unsigned int qat_uclo_calc_checksum(unsigned int reg, int ch)
466   | {
467   |  int i;
468   |  unsigned int topbit = 1 << 0xF;
469   |  unsigned int inbyte = (unsigned int)((reg >> 0x18) ^ ch);
470   |
471   | 	reg ^= inbyte << 0x8;
472   |  for (i = 0; i < 0x8; i++) {
473   |  if (reg & topbit)
474   | 			reg = (reg << 1) ^ 0x1021;
475   |  else
476   | 			reg <<= 1;
477   | 	}
478   |  return reg & 0xFFFF;
479   | }
480   |
481   | static unsigned int qat_uclo_calc_str_checksum(char *ptr, int num)
482   | {
483   |  unsigned int chksum = 0;
484   |
485   |  if (ptr)
486   |  while (num--)
487   | 			chksum = qat_uclo_calc_checksum(chksum, *ptr++);
488   |  return chksum;
489   | }
490   |
491   | static struct icp_qat_uclo_objhdr *
492   | qat_uclo_map_chunk(char *buf, struct icp_qat_uof_filehdr *file_hdr,
493   |  char *chunk_id)
494   | {
495   |  struct icp_qat_uof_filechunkhdr *file_chunk;
496   |  struct icp_qat_uclo_objhdr *obj_hdr;
497   |  char *chunk;
498   |  int i;
499   |
500   | 	file_chunk = (struct icp_qat_uof_filechunkhdr *)
501   | 		(buf + sizeof(struct icp_qat_uof_filehdr));
502   |  for (i = 0; i < file_hdr->num_chunks; i++) {
503   |  if (!strncmp(file_chunk->chunk_id, chunk_id,
504   |  ICP_QAT_UOF_OBJID_LEN)) {
505   | 			chunk = buf + file_chunk->offset;
506   |  if (file_chunk->checksum != qat_uclo_calc_str_checksum(
507   | 				chunk, file_chunk->size))
508   |  break;
509   | 			obj_hdr = kzalloc(sizeof(*obj_hdr), GFP_KERNEL);
510   |  if (!obj_hdr)
511   |  break;
512   | 			obj_hdr->file_buff = chunk;
513   | 			obj_hdr->checksum = file_chunk->checksum;
514   | 			obj_hdr->size = file_chunk->size;
515   |  return obj_hdr;
516   | 		}
517   | 		file_chunk++;
518   | 	}
519   |  return NULL;
520   | }
521   |
522   | static int
523   | qat_uclo_check_image_compat(struct icp_qat_uof_encap_obj *encap_uof_obj,
524   |  struct icp_qat_uof_image *image)
525   | {
526   |  struct icp_qat_uof_objtable *uc_var_tab, *imp_var_tab, *imp_expr_tab;
527   |  struct icp_qat_uof_objtable *neigh_reg_tab;
528   |  struct icp_qat_uof_code_page *code_page;
529   |
530   | 	code_page = (struct icp_qat_uof_code_page *)
531   | 			((char *)image + sizeof(struct icp_qat_uof_image));
532   | 	uc_var_tab = (struct icp_qat_uof_objtable *)(encap_uof_obj->beg_uof +
533   | 		     code_page->uc_var_tab_offset);
534   | 	imp_var_tab = (struct icp_qat_uof_objtable *)(encap_uof_obj->beg_uof +
535   | 		      code_page->imp_var_tab_offset);
536   | 	imp_expr_tab = (struct icp_qat_uof_objtable *)
537   | 		       (encap_uof_obj->beg_uof +
538   | 		       code_page->imp_expr_tab_offset);
539   |  if (uc_var_tab->entry_num || imp_var_tab->entry_num ||
540   | 	    imp_expr_tab->entry_num) {
541   |  pr_err("QAT: UOF can't contain imported variable to be parsed\n");
542   |  return -EINVAL;
543   | 	}
544   | 	neigh_reg_tab = (struct icp_qat_uof_objtable *)
545   | 			(encap_uof_obj->beg_uof +
546   | 			code_page->neigh_reg_tab_offset);
547   |  if (neigh_reg_tab->entry_num) {
548   |  pr_err("QAT: UOF can't contain neighbor register table\n");
549   |  return -EINVAL;
550   | 	}
551   |  if (image->numpages > 1) {
552   |  pr_err("QAT: UOF can't contain multiple pages\n");
553   |  return -EINVAL;
554   | 	}
555   |  if (ICP_QAT_SHARED_USTORE_MODE(image->ae_mode)) {
556   |  pr_err("QAT: UOF can't use shared control store feature\n");
557   |  return -EFAULT;
558   | 	}
559   |  if (RELOADABLE_CTX_SHARED_MODE(image->ae_mode)) {
560   |  pr_err("QAT: UOF can't use reloadable feature\n");
561   |  return -EFAULT;
562   | 	}
563   |  return 0;
564   | }
565   |
566   | static void qat_uclo_map_image_page(struct icp_qat_uof_encap_obj
567   | 				     *encap_uof_obj,
568   |  struct icp_qat_uof_image *img,
569   |  struct icp_qat_uclo_encap_page *page)
570   | {
571   |  struct icp_qat_uof_code_page *code_page;
572   |  struct icp_qat_uof_code_area *code_area;
573   |  struct icp_qat_uof_objtable *uword_block_tab;
574   |  struct icp_qat_uof_uword_block *uwblock;
575   |  int i;
576   |
577   | 	code_page = (struct icp_qat_uof_code_page *)
578   | 			((char *)img + sizeof(struct icp_qat_uof_image));
579   | 	page->def_page = code_page->def_page;
580   | 	page->page_region = code_page->page_region;
581   | 	page->beg_addr_v = code_page->beg_addr_v;
582   | 	page->beg_addr_p = code_page->beg_addr_p;
583   | 	code_area = (struct icp_qat_uof_code_area *)(encap_uof_obj->beg_uof +
584   | 						code_page->code_area_offset);
585   | 	page->micro_words_num = code_area->micro_words_num;
586   | 	uword_block_tab = (struct icp_qat_uof_objtable *)
587   | 			  (encap_uof_obj->beg_uof +
588   | 			  code_area->uword_block_tab);
589   | 	page->uwblock_num = uword_block_tab->entry_num;
590   | 	uwblock = (struct icp_qat_uof_uword_block *)((char *)uword_block_tab +
591   |  sizeof(struct icp_qat_uof_objtable));
592   | 	page->uwblock = (struct icp_qat_uclo_encap_uwblock *)uwblock;
593   |  for (i = 0; i < uword_block_tab->entry_num; i++)
594   | 		page->uwblock[i].micro_words =
595   | 		(uintptr_t)encap_uof_obj->beg_uof + uwblock[i].uword_offset;
596   | }
597   |
598   | static int qat_uclo_map_uimage(struct icp_qat_uclo_objhandle *obj_handle,
599   |  struct icp_qat_uclo_encapme *ae_uimage,
600   |  int max_image)
601   | {
602   |  int i, j;
603   |  struct icp_qat_uof_chunkhdr *chunk_hdr = NULL;
604   |  struct icp_qat_uof_image *image;
605   |  struct icp_qat_uof_objtable *ae_regtab;
606   |  struct icp_qat_uof_objtable *init_reg_sym_tab;
607   |  struct icp_qat_uof_objtable *sbreak_tab;
608   |  struct icp_qat_uof_encap_obj *encap_uof_obj =
609   | 					&obj_handle->encap_uof_obj;
610   |
611   |  for (j = 0; j < max_image; j++) {
    23←Loop condition is true.  Entering loop body→
    28←Loop condition is true.  Entering loop body→
612   |  chunk_hdr = qat_uclo_find_chunk(encap_uof_obj->obj_hdr,
613   |  ICP_QAT_UOF_IMAG, chunk_hdr);
614   |  if (!chunk_hdr23.1'chunk_hdr' is non-null)
    24←Taking false branch→
    29←Assuming 'chunk_hdr' is non-null→
    30←Taking false branch→
615   |  break;
616   |  image = (struct icp_qat_uof_image *)(encap_uof_obj->beg_uof +
617   | 						     chunk_hdr->offset);
618   | 		ae_regtab = (struct icp_qat_uof_objtable *)
619   | 			   (image->reg_tab_offset +
620   | 			   obj_handle->obj_hdr->file_buff);
621   | 		ae_uimage[j].ae_reg_num = ae_regtab->entry_num;
622   | 		ae_uimage[j].ae_reg = (struct icp_qat_uof_ae_reg *)
623   | 			(((char *)ae_regtab) +
624   |  sizeof(struct icp_qat_uof_objtable));
625   | 		init_reg_sym_tab = (struct icp_qat_uof_objtable *)
626   | 				   (image->init_reg_sym_tab +
627   | 				   obj_handle->obj_hdr->file_buff);
628   | 		ae_uimage[j].init_regsym_num = init_reg_sym_tab->entry_num;
629   | 		ae_uimage[j].init_regsym = (struct icp_qat_uof_init_regsym *)
630   | 			(((char *)init_reg_sym_tab) +
631   |  sizeof(struct icp_qat_uof_objtable));
632   | 		sbreak_tab = (struct icp_qat_uof_objtable *)
633   | 			(image->sbreak_tab + obj_handle->obj_hdr->file_buff);
634   | 		ae_uimage[j].sbreak_num = sbreak_tab->entry_num;
635   | 		ae_uimage[j].sbreak = (struct icp_qat_uof_sbreak *)
636   | 				      (((char *)sbreak_tab) +
637   |  sizeof(struct icp_qat_uof_objtable));
638   | 		ae_uimage[j].img_ptr = image;
639   |  if (qat_uclo_check_image_compat(encap_uof_obj, image))
    25←Taking false branch→
    31←Taking true branch→
640   |  goto out_err;
    32←Control jumps to line 651→
641   |  ae_uimage[j].page =
642   | 			kzalloc(sizeof(struct icp_qat_uclo_encap_page),
643   |  GFP_KERNEL);
644   |  if (!ae_uimage[j].page)
    26←Assuming field 'page' is non-null→
    27←Taking false branch→
645   |  goto out_err;
646   |  qat_uclo_map_image_page(encap_uof_obj, image,
647   | 					ae_uimage[j].page);
648   |  }
649   |  return j;
650   | out_err:
651   |  for (i = 0; i < j; i++)
    33←Loop condition is true.  Entering loop body→
652   |  kfree(ae_uimage[i].page);
    34←Freeing unowned field in shared error label; possible double free
653   |  return 0;
654   | }
655   |
656   | static int qat_uclo_map_ae(struct icp_qat_fw_loader_handle *handle, int max_ae)
657   | {
658   |  int i, ae;
659   |  int mflag = 0;
660   |  struct icp_qat_uclo_objhandle *obj_handle = handle->obj_handle;
661   |  unsigned long ae_mask = handle->hal_handle->ae_mask;
662   |  unsigned long cfg_ae_mask = handle->cfg_ae_mask;
663   |
664   |  for_each_set_bit(ae, &ae_mask, max_ae) {
665   |  if (!test_bit(ae, &cfg_ae_mask))
666   |  continue;
667   |
668   |  for (i = 0; i < obj_handle->uimage_num; i++) {
669   |  unsigned long ae_assigned = obj_handle->ae_uimage[i].img_ptr->ae_assigned;
670   |
671   |  if (!test_bit(ae, &ae_assigned))
672   |  continue;
673   | 			mflag = 1;
674   |  if (qat_uclo_init_ae_data(obj_handle, ae, i))
675   |  return -EINVAL;
676   | 		}
677   | 	}
678   |  if (!mflag) {
679   |  pr_err("QAT: uimage uses AE not set\n");
680   |  return -EINVAL;
681   | 	}
682   |  return 0;
683   | }
684   |
685   | static struct icp_qat_uof_strtable *
686   | qat_uclo_map_str_table(struct icp_qat_uclo_objhdr *obj_hdr,
687   |  char *tab_name, struct icp_qat_uof_strtable *str_table)
688   | {
689   |  struct icp_qat_uof_chunkhdr *chunk_hdr;
690   |
691   | 	chunk_hdr = qat_uclo_find_chunk((struct icp_qat_uof_objhdr *)
692   | 					obj_hdr->file_buff, tab_name, NULL);
693   |  if (chunk_hdr) {
694   |  int hdr_size;
695   |
696   |  memcpy(&str_table->table_len, obj_hdr->file_buff +
697   |  chunk_hdr->offset, sizeof(str_table->table_len));
698   | 		hdr_size = (char *)&str_table->strings - (char *)str_table;
699   | 		str_table->strings = (uintptr_t)obj_hdr->file_buff +
700   | 					chunk_hdr->offset + hdr_size;
701   |  return str_table;
702   | 	}
703   |  return NULL;
704   | }
705   |
706   | static void
707   | qat_uclo_map_initmem_table(struct icp_qat_uof_encap_obj *encap_uof_obj,
708   |  struct icp_qat_uclo_init_mem_table *init_mem_tab)
709   | {
710   |  struct icp_qat_uof_chunkhdr *chunk_hdr;
711   |
712   | 	chunk_hdr = qat_uclo_find_chunk(encap_uof_obj->obj_hdr,
713   |  ICP_QAT_UOF_IMEM, NULL);
714   |  if (chunk_hdr) {
715   |  memmove(&init_mem_tab->entry_num, encap_uof_obj->beg_uof +
716   |  chunk_hdr->offset, sizeof(unsigned int));
717   | 		init_mem_tab->init_mem = (struct icp_qat_uof_initmem *)
718   | 		(encap_uof_obj->beg_uof + chunk_hdr->offset +
719   |  sizeof(unsigned int));
720   | 	}
721   | }
722   |
723   | static unsigned int
724   | qat_uclo_get_dev_type(struct icp_qat_fw_loader_handle *handle)
725   | {
726   |  switch (handle->pci_dev->device) {
727   |  case PCI_DEVICE_ID_INTEL_QAT_DH895XCC:
728   |  return ICP_QAT_AC_895XCC_DEV_TYPE;
729   |  case PCI_DEVICE_ID_INTEL_QAT_C62X:
730   |  return ICP_QAT_AC_C62X_DEV_TYPE;
731   |  case PCI_DEVICE_ID_INTEL_QAT_C3XXX:
732   |  return ICP_QAT_AC_C3XXX_DEV_TYPE;
733   |  case ADF_4XXX_PCI_DEVICE_ID:
734   |  case ADF_401XX_PCI_DEVICE_ID:
735   |  case ADF_402XX_PCI_DEVICE_ID:
736   |  case ADF_420XX_PCI_DEVICE_ID:
737   |  return ICP_QAT_AC_4XXX_A_DEV_TYPE;
738   |  default:
739   |  pr_err("QAT: unsupported device 0x%x\n",
740   |  handle->pci_dev->device);
741   |  return 0;
742   | 	}
743   | }
744   |
745   | static int qat_uclo_check_uof_compat(struct icp_qat_uclo_objhandle *obj_handle)
746   | {
747   |  unsigned int maj_ver, prod_type = obj_handle->prod_type;
748   |
749   |  if (!(prod_type & obj_handle->encap_uof_obj.obj_hdr->ac_dev_type)) {
750   |  pr_err("QAT: UOF type 0x%x doesn't match with platform 0x%x\n",
751   |  obj_handle->encap_uof_obj.obj_hdr->ac_dev_type,
752   |  prod_type);
753   |  return -EINVAL;
754   | 	}
755   | 	maj_ver = obj_handle->prod_rev & 0xff;
756   |  if (obj_handle->encap_uof_obj.obj_hdr->max_cpu_ver < maj_ver ||
757   | 	    obj_handle->encap_uof_obj.obj_hdr->min_cpu_ver > maj_ver) {
758   |  pr_err("QAT: UOF majVer 0x%x out of range\n", maj_ver);
759   |  return -EINVAL;
760   | 	}
761   |  return 0;
762   | }
763   |
764   | static int qat_uclo_init_reg(struct icp_qat_fw_loader_handle *handle,
765   |  unsigned char ae, unsigned char ctx_mask,
766   |  enum icp_qat_uof_regtype reg_type,
767   |  unsigned short reg_addr, unsigned int value)
768   | {
769   |  switch (reg_type) {
770   |  case ICP_GPA_ABS:
771   |  case ICP_GPB_ABS:
772   | 		ctx_mask = 0;
773   |  fallthrough;
774   |  case ICP_GPA_REL:
775   |  case ICP_GPB_REL:
776   |  return qat_hal_init_gpr(handle, ae, ctx_mask, reg_type,
777   | 					reg_addr, value);
778   |  case ICP_SR_ABS:
779   |  case ICP_DR_ABS:
780   |  case ICP_SR_RD_ABS:
781   |  case ICP_DR_RD_ABS:
782   | 		ctx_mask = 0;
783   |  fallthrough;
784   |  case ICP_SR_REL:
785   |  case ICP_DR_REL:
786   |  case ICP_SR_RD_REL:
787   |  case ICP_DR_RD_REL:
788   |  return qat_hal_init_rd_xfer(handle, ae, ctx_mask, reg_type,
789   | 					    reg_addr, value);
790   |  case ICP_SR_WR_ABS:
791   |  case ICP_DR_WR_ABS:
936   |  return ret;
937   | 		}
938   | 		mode = ICP_QAT_LOC_TINDEX_MODE(uof_image->ae_mode);
939   | 		qat_hal_set_ae_tindex_mode(handle, ae, mode);
940   | 	}
941   |  return 0;
942   | }
943   |
944   | static int qat_uclo_set_ae_mode(struct icp_qat_fw_loader_handle *handle)
945   | {
946   |  struct icp_qat_uof_image *uof_image;
947   |  struct icp_qat_uclo_aedata *ae_data;
948   |  struct icp_qat_uclo_objhandle *obj_handle = handle->obj_handle;
949   |  unsigned long ae_mask = handle->hal_handle->ae_mask;
950   |  unsigned long cfg_ae_mask = handle->cfg_ae_mask;
951   |  unsigned char ae, s;
952   |  int error;
953   |
954   |  for_each_set_bit(ae, &ae_mask, handle->hal_handle->ae_max_num) {
955   |  if (!test_bit(ae, &cfg_ae_mask))
956   |  continue;
957   |
958   | 		ae_data = &obj_handle->ae_data[ae];
959   |  for (s = 0; s < min_t(unsigned int, ae_data->slice_num,
960   |  ICP_QAT_UCLO_MAX_CTX); s++) {
961   |  if (!obj_handle->ae_data[ae].ae_slices[s].encap_image)
962   |  continue;
963   | 			uof_image = ae_data->ae_slices[s].encap_image->img_ptr;
964   | 			error = qat_hal_set_modes(handle, obj_handle, ae,
965   | 						  uof_image);
966   |  if (error)
967   |  return error;
968   | 		}
969   | 	}
970   |  return 0;
971   | }
972   |
973   | static void qat_uclo_init_uword_num(struct icp_qat_fw_loader_handle *handle)
974   | {
975   |  struct icp_qat_uclo_objhandle *obj_handle = handle->obj_handle;
976   |  struct icp_qat_uclo_encapme *image;
977   |  int a;
978   |
979   |  for (a = 0; a < obj_handle->uimage_num; a++) {
980   | 		image = &obj_handle->ae_uimage[a];
981   | 		image->uwords_num = image->page->beg_addr_p +
982   | 					image->page->micro_words_num;
983   | 	}
984   | }
985   |
986   | static int qat_uclo_parse_uof_obj(struct icp_qat_fw_loader_handle *handle)
987   | {
988   |  struct icp_qat_uclo_objhandle *obj_handle = handle->obj_handle;
989   |  unsigned int ae;
990   |
991   | 	obj_handle->encap_uof_obj.beg_uof = obj_handle->obj_hdr->file_buff;
992   | 	obj_handle->encap_uof_obj.obj_hdr = (struct icp_qat_uof_objhdr *)
993   | 					     obj_handle->obj_hdr->file_buff;
994   | 	obj_handle->uword_in_bytes = 6;
995   | 	obj_handle->prod_type = qat_uclo_get_dev_type(handle);
996   | 	obj_handle->prod_rev = PID_MAJOR_REV |
997   | 			(PID_MINOR_REV & handle->hal_handle->revision_id);
998   |  if (qat_uclo_check_uof_compat(obj_handle)) {
    18←Taking false branch→
999   |  pr_err("QAT: UOF incompatible\n");
1000  |  return -EINVAL;
1001  | 	}
1002  |  obj_handle->uword_buf = kcalloc(UWORD_CPYBUF_SIZE, sizeof(u64),
1003  |  GFP_KERNEL);
1004  |  if (!obj_handle->uword_buf)
    19←Assuming field 'uword_buf' is non-null→
    20←Taking false branch→
1005  |  return -ENOMEM;
1006  |  obj_handle->ustore_phy_size = ICP_QAT_UCLO_MAX_USTORE;
1007  |  if (!obj_handle->obj_hdr->file_buff20.1Field 'file_buff' is non-null ||
    21←Taking false branch→
1008  |  !qat_uclo_map_str_table(obj_handle->obj_hdr, ICP_QAT_UOF_STRT,
1009  | 				    &obj_handle->str_table)) {
1010  |  pr_err("QAT: UOF doesn't have effective images\n");
1011  |  goto out_err;
1012  | 	}
1013  |  obj_handle->uimage_num =
1014  |  qat_uclo_map_uimage(obj_handle, obj_handle->ae_uimage,
    22←Calling 'qat_uclo_map_uimage'→
1015  |  ICP_QAT_UCLO_MAX_AE * ICP_QAT_UCLO_MAX_CTX);
1016  |  if (!obj_handle->uimage_num)
1017  |  goto out_err;
1018  |  if (qat_uclo_map_ae(handle, handle->hal_handle->ae_max_num)) {
1019  |  pr_err("QAT: Bad object\n");
1020  |  goto out_check_uof_aemask_err;
1021  | 	}
1022  | 	qat_uclo_init_uword_num(handle);
1023  | 	qat_uclo_map_initmem_table(&obj_handle->encap_uof_obj,
1024  | 				   &obj_handle->init_mem_tab);
1025  |  if (qat_uclo_set_ae_mode(handle))
1026  |  goto out_check_uof_aemask_err;
1027  |  return 0;
1028  | out_check_uof_aemask_err:
1029  |  for (ae = 0; ae < obj_handle->uimage_num; ae++)
1030  | 		kfree(obj_handle->ae_uimage[ae].page);
1031  | out_err:
1032  | 	kfree(obj_handle->uword_buf);
1033  |  return -EFAULT;
1034  | }
1035  |
1036  | static int qat_uclo_map_suof_file_hdr(struct icp_qat_fw_loader_handle *handle,
1037  |  struct icp_qat_suof_filehdr *suof_ptr,
1038  |  int suof_size)
1039  | {
1040  |  unsigned int check_sum = 0;
1041  |  unsigned int min_ver_offset = 0;
1042  |  struct icp_qat_suof_handle *suof_handle = handle->sobj_handle;
1043  |
1044  | 	suof_handle->file_id = ICP_QAT_SUOF_FID;
1045  | 	suof_handle->suof_buf = (char *)suof_ptr;
1565  |  pr_err("QAT: firmware load failed timeout %x\n", retry);
1566  |  return -EINVAL;
1567  | 		}
1568  | 	}
1569  |  return 0;
1570  | }
1571  |
1572  | static int qat_uclo_map_suof_obj(struct icp_qat_fw_loader_handle *handle,
1573  |  void *addr_ptr, int mem_size)
1574  | {
1575  |  struct icp_qat_suof_handle *suof_handle;
1576  |
1577  | 	suof_handle = kzalloc(sizeof(*suof_handle), GFP_KERNEL);
1578  |  if (!suof_handle)
1579  |  return -ENOMEM;
1580  | 	handle->sobj_handle = suof_handle;
1581  |  if (qat_uclo_map_suof(handle, addr_ptr, mem_size)) {
1582  | 		qat_uclo_del_suof(handle);
1583  |  pr_err("QAT: map SUOF failed\n");
1584  |  return -EINVAL;
1585  | 	}
1586  |  return 0;
1587  | }
1588  |
1589  | int qat_uclo_wr_mimage(struct icp_qat_fw_loader_handle *handle,
1590  |  void *addr_ptr, int mem_size)
1591  | {
1592  |  struct icp_qat_fw_auth_desc *desc = NULL;
1593  |  int status = 0;
1594  |  int ret;
1595  |
1596  | 	ret = qat_uclo_check_image(handle, addr_ptr, mem_size, CSS_MMP_FIRMWARE);
1597  |  if (ret)
1598  |  return ret;
1599  |
1600  |  if (handle->chip_info->fw_auth) {
1601  | 		status = qat_uclo_map_auth_fw(handle, addr_ptr, mem_size, &desc);
1602  |  if (!status)
1603  | 			status = qat_uclo_auth_fw(handle, desc);
1604  | 		qat_uclo_ummap_auth_fw(handle, &desc);
1605  | 	} else {
1606  |  if (handle->chip_info->mmp_sram_size < mem_size) {
1607  |  pr_err("QAT: MMP size is too large: 0x%x\n", mem_size);
1608  |  return -EFBIG;
1609  | 		}
1610  | 		qat_uclo_wr_sram_by_words(handle, 0, addr_ptr, mem_size);
1611  | 	}
1612  |  return status;
1613  | }
1614  |
1615  | static int qat_uclo_map_uof_obj(struct icp_qat_fw_loader_handle *handle,
1616  |  void *addr_ptr, int mem_size)
1617  | {
1618  |  struct icp_qat_uof_filehdr *filehdr;
1619  |  struct icp_qat_uclo_objhandle *objhdl;
1620  |
1621  | 	objhdl = kzalloc(sizeof(*objhdl), GFP_KERNEL);
1622  |  if (!objhdl)
    11←Assuming 'objhdl' is non-null→
    12←Taking false branch→
1623  |  return -ENOMEM;
1624  |  objhdl->obj_buf = kmemdup(addr_ptr, mem_size, GFP_KERNEL);
1625  |  if (!objhdl->obj_buf)
    13←Assuming field 'obj_buf' is non-null→
    14←Taking false branch→
1626  |  goto out_objbuf_err;
1627  |  filehdr = (struct icp_qat_uof_filehdr *)objhdl->obj_buf;
1628  |  if (qat_uclo_check_uof_format(filehdr))
    15←Taking false branch→
1629  |  goto out_objhdr_err;
1630  |  objhdl->obj_hdr = qat_uclo_map_chunk((char *)objhdl->obj_buf, filehdr,
1631  |  ICP_QAT_UOF_OBJS);
1632  |  if (!objhdl->obj_hdr15.1Field 'obj_hdr' is non-null) {
    16←Taking false branch→
1633  |  pr_err("QAT: object file chunk is null\n");
1634  |  goto out_objhdr_err;
1635  | 	}
1636  |  handle->obj_handle = objhdl;
1637  |  if (qat_uclo_parse_uof_obj(handle))
    17←Calling 'qat_uclo_parse_uof_obj'→
1638  |  goto out_overlay_obj_err;
1639  |  return 0;
1640  |
1641  | out_overlay_obj_err:
1642  | 	handle->obj_handle = NULL;
1643  | 	kfree(objhdl->obj_hdr);
1644  | out_objhdr_err:
1645  | 	kfree(objhdl->obj_buf);
1646  | out_objbuf_err:
1647  | 	kfree(objhdl);
1648  |  return -ENOMEM;
1649  | }
1650  |
1651  | static int qat_uclo_map_mof_file_hdr(struct icp_qat_fw_loader_handle *handle,
1652  |  struct icp_qat_mof_file_hdr *mof_ptr,
1653  | 				     u32 mof_size)
1654  | {
1655  |  struct icp_qat_mof_handle *mobj_handle = handle->mobj_handle;
1656  |  unsigned int min_ver_offset;
1657  |  unsigned int checksum;
1658  |
1659  | 	mobj_handle->file_id = ICP_QAT_MOF_FID;
1660  | 	mobj_handle->mof_buf = (char *)mof_ptr;
1661  | 	mobj_handle->mof_size = mof_size;
1662  |
1663  | 	min_ver_offset = mof_size - offsetof(struct icp_qat_mof_file_hdr,
1664  |  min_ver);
1665  | 	checksum = qat_uclo_calc_str_checksum(&mof_ptr->min_ver,
1666  | 					      min_ver_offset);
1667  |  if (checksum != mof_ptr->checksum) {
1841  | 				u32 mof_size, const char *obj_name,
1842  |  char **obj_ptr, unsigned int *obj_size)
1843  | {
1844  |  struct icp_qat_mof_chunkhdr *mof_chunkhdr;
1845  |  unsigned int file_id = mof_ptr->file_id;
1846  |  struct icp_qat_mof_handle *mobj_handle;
1847  |  unsigned short chunks_num;
1848  |  unsigned int i;
1849  |  int ret;
1850  |
1851  |  if (file_id == ICP_QAT_UOF_FID || file_id == ICP_QAT_SUOF_FID) {
1852  |  if (obj_ptr)
1853  | 			*obj_ptr = (char *)mof_ptr;
1854  |  if (obj_size)
1855  | 			*obj_size = mof_size;
1856  |  return 0;
1857  | 	}
1858  |  if (qat_uclo_check_mof_format(mof_ptr))
1859  |  return -EINVAL;
1860  |
1861  | 	mobj_handle = kzalloc(sizeof(*mobj_handle), GFP_KERNEL);
1862  |  if (!mobj_handle)
1863  |  return -ENOMEM;
1864  |
1865  | 	handle->mobj_handle = mobj_handle;
1866  | 	ret = qat_uclo_map_mof_file_hdr(handle, mof_ptr, mof_size);
1867  |  if (ret)
1868  |  return ret;
1869  |
1870  | 	mof_chunkhdr = (void *)mof_ptr + sizeof(*mof_ptr);
1871  | 	chunks_num = mof_ptr->num_chunks;
1872  |
1873  |  /* Parse MOF file chunks */
1874  |  for (i = 0; i < chunks_num; i++)
1875  | 		qat_uclo_map_mof_chunk(mobj_handle, &mof_chunkhdr[i]);
1876  |
1877  |  /* All sym_objs uobjs and sobjs should be available */
1878  |  if (!mobj_handle->sym_str ||
1879  | 	    (!mobj_handle->uobjs_hdr && !mobj_handle->sobjs_hdr))
1880  |  return -EINVAL;
1881  |
1882  | 	ret = qat_uclo_map_objs_from_mof(mobj_handle);
1883  |  if (ret)
1884  |  return ret;
1885  |
1886  |  /* Seek specified uof object in MOF */
1887  |  return qat_uclo_seek_obj_inside_mof(mobj_handle, obj_name,
1888  | 					    obj_ptr, obj_size);
1889  | }
1890  |
1891  | int qat_uclo_map_obj(struct icp_qat_fw_loader_handle *handle,
1892  |  void *addr_ptr, u32 mem_size, const char *obj_name)
1893  | {
1894  |  char *obj_addr;
1895  | 	u32 obj_size;
1896  |  int ret;
1897  |
1898  |  BUILD_BUG_ON(ICP_QAT_UCLO_MAX_AE >=
    1Taking false branch→
1899  |  (sizeof(handle->hal_handle->ae_mask) * 8));
1900  |
1901  |  if (!handle || !addr_ptr || mem_size < 24)
    2←Assuming 'handle' is non-null→
    3←Assuming 'addr_ptr' is non-null→
    4←Assuming 'mem_size' is >= 24→
    5←Taking false branch→
1902  |  return -EINVAL;
1903  |
1904  |  if (obj_name) {
    6←Assuming 'obj_name' is null→
    7←Taking false branch→
1905  | 		ret = qat_uclo_map_mof_obj(handle, addr_ptr, mem_size, obj_name,
1906  | 					   &obj_addr, &obj_size);
1907  |  if (ret)
1908  |  return ret;
1909  | 	} else {
1910  |  obj_addr = addr_ptr;
1911  |  obj_size = mem_size;
1912  | 	}
1913  |
1914  |  return (handle->chip_info->fw_auth) ?
    8←Assuming field 'fw_auth' is false→
    9←'?' condition is false→
1915  | 			qat_uclo_map_suof_obj(handle, obj_addr, obj_size) :
1916  |  qat_uclo_map_uof_obj(handle, obj_addr, obj_size);
    10←Calling 'qat_uclo_map_uof_obj'→
1917  | }
1918  |
1919  | void qat_uclo_del_obj(struct icp_qat_fw_loader_handle *handle)
1920  | {
1921  |  struct icp_qat_uclo_objhandle *obj_handle = handle->obj_handle;
1922  |  unsigned int a;
1923  |
1924  |  if (handle->mobj_handle)
1925  | 		qat_uclo_del_mof(handle);
1926  |  if (handle->sobj_handle)
1927  | 		qat_uclo_del_suof(handle);
1928  |  if (!obj_handle)
1929  |  return;
1930  |
1931  | 	kfree(obj_handle->uword_buf);
1932  |  for (a = 0; a < obj_handle->uimage_num; a++)
1933  | 		kfree(obj_handle->ae_uimage[a].page);
1934  |
1935  |  for (a = 0; a < handle->hal_handle->ae_max_num; a++)
1936  | 		qat_uclo_free_ae_data(&obj_handle->ae_data[a]);
1937  |
1938  | 	kfree(obj_handle->obj_hdr);
1939  | 	kfree(obj_handle->obj_buf);
1940  | 	kfree(obj_handle);
1941  | 	handle->obj_handle = NULL;
1942  | }
1943  |
1944  | static void qat_uclo_fill_uwords(struct icp_qat_uclo_objhandle *obj_handle,
1945  |  struct icp_qat_uclo_encap_page *encap_page,
1946  | 				 u64 *uword, unsigned int addr_p,

Analysis:
- Decision: NotABug
- Reason: The flagged code does not match the target bug pattern and is not a real bug. In qat_uclo_map_uimage(), the shared error label out_err only frees ae_uimage[i].page for i < j. For each prior iteration (0..j-1), ae_uimage[i].page was allocated in this function via kzalloc, and no callee frees it; thus the function owns these allocations and correctly frees them on error. If the failure occurs before allocating the current j’s page (e.g., compatibility check fails), j remains unchanged and the loop frees only previously allocated pages. If allocation of page fails at index j, again only earlier pages (which were successfully allocated) are freed. The object handle struct is allocated with kzalloc, ensuring ae_uimage[] entries are initialized to NULL, so even in edge cases kfree(NULL) would be safe. There is no callee-managed memory being freed here, and no double-free: other cleanup paths either free these pages only on success paths later, or, on parse failure, the function returning error ensures pages are either already freed here or freed exactly once in later, separate cleanup. This differs from the target pattern (freeing possibly callee-freed/unallocated memory via a shared error label), so the report is a false positive.

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

    // Suppress known false positives (ownership known on path, non-error labels, or reset+realloc idiom).
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
