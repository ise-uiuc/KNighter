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

File:| sound/soc/codecs/aw88395/aw88395_lib.c
---|---
Warning:| line 428, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


311   |  return ret;
312   | 		}
313   | 	}
314   |
315   |  return 0;
316   | }
317   |
318   | static int aw_dev_parse_raw_reg(unsigned char *data, unsigned int data_len,
319   |  struct aw_prof_desc *prof_desc)
320   | {
321   | 	prof_desc->sec_desc[AW88395_DATA_TYPE_REG].data = data;
322   | 	prof_desc->sec_desc[AW88395_DATA_TYPE_REG].len = data_len;
323   |
324   | 	prof_desc->prof_st = AW88395_PROFILE_OK;
325   |
326   |  return 0;
327   | }
328   |
329   | static int aw_dev_parse_raw_dsp_cfg(unsigned char *data, unsigned int data_len,
330   |  struct aw_prof_desc *prof_desc)
331   | {
332   |  if (data_len & 0x01)
333   |  return -EINVAL;
334   |
335   | 	swab16_array((u16 *)data, data_len >> 1);
336   |
337   | 	prof_desc->sec_desc[AW88395_DATA_TYPE_DSP_CFG].data = data;
338   | 	prof_desc->sec_desc[AW88395_DATA_TYPE_DSP_CFG].len = data_len;
339   |
340   | 	prof_desc->prof_st = AW88395_PROFILE_OK;
341   |
342   |  return 0;
343   | }
344   |
345   | static int aw_dev_parse_raw_dsp_fw(unsigned char *data,	unsigned int data_len,
346   |  struct aw_prof_desc *prof_desc)
347   | {
348   |  if (data_len & 0x01)
349   |  return -EINVAL;
350   |
351   | 	swab16_array((u16 *)data, data_len >> 1);
352   |
353   | 	prof_desc->sec_desc[AW88395_DATA_TYPE_DSP_FW].data = data;
354   | 	prof_desc->sec_desc[AW88395_DATA_TYPE_DSP_FW].len = data_len;
355   |
356   | 	prof_desc->prof_st = AW88395_PROFILE_OK;
357   |
358   |  return 0;
359   | }
360   |
361   | static int aw_dev_prof_parse_multi_bin(struct aw_device *aw_dev, unsigned char *data,
362   |  unsigned int data_len, struct aw_prof_desc *prof_desc)
363   | {
364   |  struct aw_bin *aw_bin;
365   |  int ret;
366   |  int i;
367   |
368   | 	aw_bin = devm_kzalloc(aw_dev->dev, data_len + sizeof(struct aw_bin), GFP_KERNEL);
369   |  if (!aw_bin)
    17←Assuming 'aw_bin' is non-null→
    18←Taking false branch→
370   |  return -ENOMEM;
371   |
372   |  aw_bin->info.len = data_len;
373   |  memcpy(aw_bin->info.data, data, data_len);
    19←Assuming the condition is false→
    20←Taking true branch→
    21←Taking true branch→
    22←Taking true branch→
    23←Loop condition is false.  Exiting loop→
    24←Loop condition is false.  Exiting loop→
    25←Loop condition is false.  Exiting loop→
374   |
375   | 	ret = aw_parsing_bin_file(aw_dev, aw_bin);
376   |  if (ret < 0) {
    26←Assuming 'ret' is >= 0→
    27←Taking false branch→
377   |  dev_err(aw_dev->dev, "parse bin failed");
378   |  goto parse_bin_failed;
379   | 	}
380   |
381   |  for (i = 0; i < aw_bin->all_bin_parse_num; i++) {
    28←Assuming 'i' is >= field 'all_bin_parse_num'→
    29←Loop condition is false. Execution continues on line 424→
382   |  switch (aw_bin->header_info[i].bin_data_type) {
383   |  case DATA_TYPE_REGISTER:
384   | 			prof_desc->sec_desc[AW88395_DATA_TYPE_REG].len =
385   | 					aw_bin->header_info[i].valid_data_len;
386   | 			prof_desc->sec_desc[AW88395_DATA_TYPE_REG].data =
387   | 					data + aw_bin->header_info[i].valid_data_addr;
388   |  break;
389   |  case DATA_TYPE_DSP_REG:
390   |  if (aw_bin->header_info[i].valid_data_len & 0x01) {
391   | 				ret = -EINVAL;
392   |  goto parse_bin_failed;
393   | 			}
394   |
395   | 			swab16_array((u16 *)(data + aw_bin->header_info[i].valid_data_addr),
396   | 					aw_bin->header_info[i].valid_data_len >> 1);
397   |
398   | 			prof_desc->sec_desc[AW88395_DATA_TYPE_DSP_CFG].len =
399   | 					aw_bin->header_info[i].valid_data_len;
400   | 			prof_desc->sec_desc[AW88395_DATA_TYPE_DSP_CFG].data =
401   | 					data + aw_bin->header_info[i].valid_data_addr;
402   |  break;
403   |  case DATA_TYPE_DSP_FW:
404   |  case DATA_TYPE_SOC_APP:
405   |  if (aw_bin->header_info[i].valid_data_len & 0x01) {
406   | 				ret = -EINVAL;
407   |  goto parse_bin_failed;
408   | 			}
409   |
410   | 			swab16_array((u16 *)(data + aw_bin->header_info[i].valid_data_addr),
411   | 					aw_bin->header_info[i].valid_data_len >> 1);
412   |
413   | 			prof_desc->fw_ver = aw_bin->header_info[i].app_version;
414   | 			prof_desc->sec_desc[AW88395_DATA_TYPE_DSP_FW].len =
415   | 					aw_bin->header_info[i].valid_data_len;
416   | 			prof_desc->sec_desc[AW88395_DATA_TYPE_DSP_FW].data =
417   | 					data + aw_bin->header_info[i].valid_data_addr;
418   |  break;
419   |  default:
420   |  dev_dbg(aw_dev->dev, "bin_data_type not found");
421   |  break;
422   | 		}
423   | 	}
424   |  prof_desc->prof_st = AW88395_PROFILE_OK;
425   |  ret =  0;
426   |
427   | parse_bin_failed:
428   |  devm_kfree(aw_dev->dev, aw_bin);
    30←Freeing unowned field in shared error label; possible double free
429   |  return ret;
430   | }
431   |
432   | static int aw_dev_parse_reg_bin_with_hdr(struct aw_device *aw_dev,
433   | 			uint8_t *data, uint32_t data_len, struct aw_prof_desc *prof_desc)
434   | {
435   |  struct aw_bin *aw_bin;
436   |  int ret;
437   |
438   | 	aw_bin = devm_kzalloc(aw_dev->dev, data_len + sizeof(*aw_bin), GFP_KERNEL);
439   |  if (!aw_bin)
440   |  return -ENOMEM;
441   |
442   | 	aw_bin->info.len = data_len;
443   |  memcpy(aw_bin->info.data, data, data_len);
444   |
445   | 	ret = aw_parsing_bin_file(aw_dev, aw_bin);
446   |  if (ret < 0) {
447   |  dev_err(aw_dev->dev, "parse bin failed");
448   |  goto parse_bin_failed;
449   | 	}
450   |
451   |  if ((aw_bin->all_bin_parse_num != 1) ||
452   | 		(aw_bin->header_info[0].bin_data_type != DATA_TYPE_REGISTER)) {
453   |  dev_err(aw_dev->dev, "bin num or type error");
454   | 		ret = -EINVAL;
455   |  goto parse_bin_failed;
456   | 	}
457   |
458   | 	prof_desc->sec_desc[AW88395_DATA_TYPE_REG].data =
459   | 				data + aw_bin->header_info[0].valid_data_addr;
460   | 	prof_desc->sec_desc[AW88395_DATA_TYPE_REG].len =
461   | 				aw_bin->header_info[0].valid_data_len;
462   | 	prof_desc->prof_st = AW88395_PROFILE_OK;
463   |
464   | 	devm_kfree(aw_dev->dev, aw_bin);
465   | 	aw_bin = NULL;
466   |
467   |  return 0;
468   |
469   | parse_bin_failed:
470   | 	devm_kfree(aw_dev->dev, aw_bin);
471   | 	aw_bin = NULL;
472   |  return ret;
473   | }
474   |
475   | static int aw_dev_parse_data_by_sec_type(struct aw_device *aw_dev, struct aw_cfg_hdr *cfg_hdr,
476   |  struct aw_cfg_dde *cfg_dde, struct aw_prof_desc *scene_prof_desc)
477   | {
478   |  switch (cfg_dde->data_type) {
    15←Control jumps to 'case ACF_SEC_TYPE_MULTIPLE_BIN:'  at line 489→
479   |  case ACF_SEC_TYPE_REG:
480   |  return aw_dev_parse_raw_reg((u8 *)cfg_hdr + cfg_dde->data_offset,
481   | 				cfg_dde->data_size, scene_prof_desc);
482   |  case ACF_SEC_TYPE_DSP_CFG:
483   |  return aw_dev_parse_raw_dsp_cfg((u8 *)cfg_hdr + cfg_dde->data_offset,
484   | 				cfg_dde->data_size, scene_prof_desc);
485   |  case ACF_SEC_TYPE_DSP_FW:
486   |  return aw_dev_parse_raw_dsp_fw(
487   | 				(u8 *)cfg_hdr + cfg_dde->data_offset,
488   | 				cfg_dde->data_size, scene_prof_desc);
489   |  case ACF_SEC_TYPE_MULTIPLE_BIN:
490   |  return aw_dev_prof_parse_multi_bin(
    16←Calling 'aw_dev_prof_parse_multi_bin'→
491   |  aw_dev, (u8 *)cfg_hdr + cfg_dde->data_offset,
492   |  cfg_dde->data_size, scene_prof_desc);
493   |  case ACF_SEC_TYPE_HDR_REG:
494   |  return aw_dev_parse_reg_bin_with_hdr(aw_dev, (u8 *)cfg_hdr + cfg_dde->data_offset,
495   | 				cfg_dde->data_size, scene_prof_desc);
496   |  default:
497   |  dev_err(aw_dev->dev, "%s cfg_dde->data_type = %d\n", __func__, cfg_dde->data_type);
498   |  break;
499   | 	}
500   |
501   |  return 0;
502   | }
503   |
504   | static int aw_dev_parse_dev_type(struct aw_device *aw_dev,
505   |  struct aw_cfg_hdr *prof_hdr, struct aw_all_prof_info *all_prof_info)
506   | {
507   |  struct aw_cfg_dde *cfg_dde =
508   | 		(struct aw_cfg_dde *)((char *)prof_hdr + prof_hdr->hdr_offset);
509   |  int sec_num = 0;
510   |  int ret, i;
511   |
512   |  for (i = 0; i < prof_hdr->ddt_num; i++) {
    6←Assuming 'i' is < field 'ddt_num'→
513   |  if ((aw_dev->i2c->adapter->nr == cfg_dde[i].dev_bus) &&
    7←Assuming field 'nr' is equal to field 'dev_bus'→
    11←Taking true branch→
514   | 		    (aw_dev->i2c->addr == cfg_dde[i].dev_addr) &&
    8←Assuming field 'addr' is equal to field 'dev_addr'→
515   | 		    (cfg_dde[i].type == AW88395_DEV_TYPE_ID) &&
    9←Assuming field 'type' is equal to AW88395_DEV_TYPE_ID→
516   | 		    (cfg_dde[i].data_type != ACF_SEC_TYPE_MONITOR)) {
    10←Assuming field 'data_type' is not equal to ACF_SEC_TYPE_MONITOR→
517   |  if (cfg_dde[i].dev_profile >= AW88395_PROFILE_MAX) {
    12←Assuming field 'dev_profile' is < AW88395_PROFILE_MAX→
    13←Taking false branch→
518   |  dev_err(aw_dev->dev, "dev_profile [%d] overflow",
519   |  cfg_dde[i].dev_profile);
520   |  return -EINVAL;
521   | 			}
522   |  aw_dev->prof_data_type = cfg_dde[i].data_type;
523   |  ret = aw_dev_parse_data_by_sec_type(aw_dev, prof_hdr, &cfg_dde[i],
    14←Calling 'aw_dev_parse_data_by_sec_type'→
524   |  &all_prof_info->prof_desc[cfg_dde[i].dev_profile]);
525   |  if (ret < 0) {
526   |  dev_err(aw_dev->dev, "parse failed");
527   |  return ret;
528   | 			}
529   | 			sec_num++;
530   | 		}
531   | 	}
532   |
533   |  if (sec_num == 0) {
534   |  dev_dbg(aw_dev->dev, "get dev type num is %d, please use default", sec_num);
535   |  return AW88395_DEV_TYPE_NONE;
536   | 	}
537   |
538   |  return AW88395_DEV_TYPE_OK;
539   | }
540   |
541   | static int aw_dev_parse_dev_default_type(struct aw_device *aw_dev,
542   |  struct aw_cfg_hdr *prof_hdr, struct aw_all_prof_info *all_prof_info)
543   | {
544   |  struct aw_cfg_dde *cfg_dde =
545   | 		(struct aw_cfg_dde *)((char *)prof_hdr + prof_hdr->hdr_offset);
546   |  int sec_num = 0;
547   |  int ret, i;
548   |
549   |  for (i = 0; i < prof_hdr->ddt_num; i++) {
550   |  if ((aw_dev->channel == cfg_dde[i].dev_index) &&
551   | 		    (cfg_dde[i].type == AW88395_DEV_DEFAULT_TYPE_ID) &&
552   | 		    (cfg_dde[i].data_type != ACF_SEC_TYPE_MONITOR)) {
553   |  if (cfg_dde[i].dev_profile >= AW88395_PROFILE_MAX) {
554   |  dev_err(aw_dev->dev, "dev_profile [%d] overflow",
628   |  for (i = 0; i < AW88395_PROFILE_MAX; i++) {
629   |  if (prof_desc[i].prof_st == AW88395_PROFILE_OK) {
630   | 			sec_desc = prof_desc[i].sec_desc;
631   |  if ((sec_desc[AW88395_DATA_TYPE_REG].data != NULL) &&
632   | 			    (sec_desc[AW88395_DATA_TYPE_REG].len != 0) &&
633   | 			    (sec_desc[AW88395_DATA_TYPE_DSP_CFG].data != NULL) &&
634   | 			    (sec_desc[AW88395_DATA_TYPE_DSP_CFG].len != 0) &&
635   | 			    (sec_desc[AW88395_DATA_TYPE_DSP_FW].data != NULL) &&
636   | 			    (sec_desc[AW88395_DATA_TYPE_DSP_FW].len != 0))
637   | 				prof_info->count++;
638   | 		}
639   | 	}
640   |
641   |  dev_dbg(aw_dev->dev, "get valid profile:%d", aw_dev->prof_info.count);
642   |
643   |  if (!prof_info->count) {
644   |  dev_err(aw_dev->dev, "no profile data");
645   |  return -EPERM;
646   | 	}
647   |
648   | 	prof_info->prof_desc = devm_kcalloc(aw_dev->dev,
649   | 					prof_info->count, sizeof(struct aw_prof_desc),
650   |  GFP_KERNEL);
651   |  if (!prof_info->prof_desc)
652   |  return -ENOMEM;
653   |
654   |  for (i = 0; i < AW88395_PROFILE_MAX; i++) {
655   |  if (prof_desc[i].prof_st == AW88395_PROFILE_OK) {
656   | 			sec_desc = prof_desc[i].sec_desc;
657   |  if ((sec_desc[AW88395_DATA_TYPE_REG].data != NULL) &&
658   | 			    (sec_desc[AW88395_DATA_TYPE_REG].len != 0) &&
659   | 			    (sec_desc[AW88395_DATA_TYPE_DSP_CFG].data != NULL) &&
660   | 			    (sec_desc[AW88395_DATA_TYPE_DSP_CFG].len != 0) &&
661   | 			    (sec_desc[AW88395_DATA_TYPE_DSP_FW].data != NULL) &&
662   | 			    (sec_desc[AW88395_DATA_TYPE_DSP_FW].len != 0)) {
663   |  if (num >= prof_info->count) {
664   |  dev_err(aw_dev->dev, "overflow count[%d]",
665   |  prof_info->count);
666   |  return -EINVAL;
667   | 				}
668   | 				prof_info->prof_desc[num] = prof_desc[i];
669   | 				prof_info->prof_desc[num].id = i;
670   | 				num++;
671   | 			}
672   | 		}
673   | 	}
674   |
675   |  return 0;
676   | }
677   |
678   | static int aw_dev_load_cfg_by_hdr(struct aw_device *aw_dev,
679   |  struct aw_cfg_hdr *prof_hdr)
680   | {
681   |  struct aw_all_prof_info *all_prof_info;
682   |  int ret;
683   |
684   | 	all_prof_info = devm_kzalloc(aw_dev->dev, sizeof(struct aw_all_prof_info), GFP_KERNEL);
685   |  if (!all_prof_info)
    3←Assuming 'all_prof_info' is non-null→
    4←Taking false branch→
686   |  return -ENOMEM;
687   |
688   |  ret = aw_dev_parse_dev_type(aw_dev, prof_hdr, all_prof_info);
    5←Calling 'aw_dev_parse_dev_type'→
689   |  if (ret < 0) {
690   |  goto exit;
691   | 	} else if (ret == AW88395_DEV_TYPE_NONE) {
692   |  dev_dbg(aw_dev->dev, "get dev type num is 0, parse default dev");
693   | 		ret = aw_dev_parse_dev_default_type(aw_dev, prof_hdr, all_prof_info);
694   |  if (ret < 0)
695   |  goto exit;
696   | 	}
697   |
698   |  switch (aw_dev->prof_data_type) {
699   |  case ACF_SEC_TYPE_MULTIPLE_BIN:
700   | 		ret = aw_dev_cfg_get_multiple_valid_prof(aw_dev, all_prof_info);
701   |  break;
702   |  case ACF_SEC_TYPE_HDR_REG:
703   | 		ret = aw_dev_cfg_get_reg_valid_prof(aw_dev, all_prof_info);
704   |  break;
705   |  default:
706   |  dev_err(aw_dev->dev, "unsupport data type\n");
707   | 		ret = -EINVAL;
708   |  break;
709   | 	}
710   |  if (!ret)
711   | 		aw_dev->prof_info.prof_name_list = profile_name;
712   |
713   | exit:
714   | 	devm_kfree(aw_dev->dev, all_prof_info);
715   |  return ret;
716   | }
717   |
718   | static int aw_dev_create_prof_name_list_v1(struct aw_device *aw_dev)
957   |  case AW88395_DEV_TYPE_ID:
958   | 		ret = aw_dev_parse_dev_type_v1(aw_dev, cfg_hdr);
959   |  break;
960   |  case AW88395_DEV_DEFAULT_TYPE_ID:
961   | 		ret = aw_dev_parse_default_type_v1(aw_dev, cfg_hdr);
962   |  break;
963   |  default:
964   |  dev_err(aw_dev->dev, "prof type matched failed, get num[%d]",
965   |  aw_dev->prof_info.prof_type);
966   | 		ret =  -EINVAL;
967   |  break;
968   | 	}
969   |
970   |  return ret;
971   | }
972   |
973   | static int aw_dev_load_cfg_by_hdr_v1(struct aw_device *aw_dev,
974   |  struct aw_container *aw_cfg)
975   | {
976   |  struct aw_cfg_hdr *cfg_hdr = (struct aw_cfg_hdr *)aw_cfg->data;
977   |  struct aw_prof_info *prof_info = &aw_dev->prof_info;
978   |  int ret;
979   |
980   | 	ret = aw_dev_parse_scene_count_v1(aw_dev, aw_cfg, &prof_info->count);
981   |  if (ret < 0) {
982   |  dev_err(aw_dev->dev, "get scene count failed");
983   |  return ret;
984   | 	}
985   |
986   | 	prof_info->prof_desc = devm_kcalloc(aw_dev->dev,
987   | 					prof_info->count, sizeof(struct aw_prof_desc),
988   |  GFP_KERNEL);
989   |  if (!prof_info->prof_desc)
990   |  return -ENOMEM;
991   |
992   | 	ret = aw_dev_parse_by_hdr_v1(aw_dev, cfg_hdr);
993   |  if (ret < 0) {
994   |  dev_err(aw_dev->dev, "parse hdr failed");
995   |  return ret;
996   | 	}
997   |
998   | 	ret = aw_dev_create_prof_name_list_v1(aw_dev);
999   |  if (ret < 0) {
1000  |  dev_err(aw_dev->dev, "create prof name list failed");
1001  |  return ret;
1002  | 	}
1003  |
1004  |  return 0;
1005  | }
1006  |
1007  | int aw88395_dev_cfg_load(struct aw_device *aw_dev, struct aw_container *aw_cfg)
1008  | {
1009  |  struct aw_cfg_hdr *cfg_hdr;
1010  |  int ret;
1011  |
1012  | 	cfg_hdr = (struct aw_cfg_hdr *)aw_cfg->data;
1013  |
1014  |  switch (cfg_hdr->hdr_version) {
    1Control jumps to 'case AW88395_CFG_HDR_VER:'  at line 1015→
1015  |  case AW88395_CFG_HDR_VER:
1016  |  ret = aw_dev_load_cfg_by_hdr(aw_dev, cfg_hdr);
    2←Calling 'aw_dev_load_cfg_by_hdr'→
1017  |  if (ret < 0) {
1018  |  dev_err(aw_dev->dev, "hdr_version[0x%x] parse failed",
1019  |  cfg_hdr->hdr_version);
1020  |  return ret;
1021  | 		}
1022  |  break;
1023  |  case AW88395_CFG_HDR_VER_V1:
1024  | 		ret = aw_dev_load_cfg_by_hdr_v1(aw_dev, aw_cfg);
1025  |  if (ret < 0) {
1026  |  dev_err(aw_dev->dev, "hdr_version[0x%x] parse failed",
1027  |  cfg_hdr->hdr_version);
1028  |  return ret;
1029  | 		}
1030  |  break;
1031  |  default:
1032  |  dev_err(aw_dev->dev, "unsupported hdr_version [0x%x]", cfg_hdr->hdr_version);
1033  |  return -EINVAL;
1034  | 	}
1035  | 	aw_dev->fw_status = AW88395_DEV_FW_OK;
1036  |
1037  |  return 0;
1038  | }
1039  | EXPORT_SYMBOL_GPL(aw88395_dev_cfg_load);
1040  |
1041  | static int aw_dev_check_cfg_by_hdr(struct aw_device *aw_dev, struct aw_container *aw_cfg)
1042  | {
1043  |  unsigned int end_data_offset;
1044  |  struct aw_cfg_hdr *cfg_hdr;
1045  |  struct aw_cfg_dde *cfg_dde;
1046  |  unsigned int act_data = 0;

Analysis:
- Decision: NotABug
- Reason: The flagged code frees a resource that is definitively owned by the function, not by a callee. In aw_dev_prof_parse_multi_bin(), aw_bin is allocated with devm_kzalloc() in this function, and on all exit paths (both success and error) it is released via devm_kfree() at the shared label. If allocation fails, the function returns early and never reaches the label, so there is no free of an uninitialized pointer. There is no evidence that the callee (aw_parsing_bin_file()) frees aw_bin; in fact, other functions in the same file follow the same pattern (allocate aw_bin, call aw_parsing_bin_file(), then devm_kfree() it), which would be unsafe if the callee freed it. Furthermore, devm_kfree() is the correct way to release devm-managed allocations early; it removes the resource from the devres list, preventing double-free at device teardown. This does not match the target bug pattern (freeing callee-managed/conditionally allocated memory via a shared error label leading to double free). The shared label here only frees memory allocated in this function and always owned by it, so there is no real bug and no match to the specified pattern.

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

  // Per-function: fields directly assigned from allocator calls within this function.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::SmallPtrSet<const FieldDecl*, 16>> FuncLocallyAllocFields;

  // Per-function: for each label, keep the list of concrete goto statements targeting it.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>>> FuncLabelGotos;

  // Per-function: earliest source location where a given FieldDecl is assigned from an allocator call.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const FieldDecl*, SourceLocation>> FuncFieldFirstAllocLoc;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Freeing unowned field in shared error label; possible double free", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to collect labels, gotos, and fields locally assigned from allocators.
  struct FuncInfoCollector : public RecursiveASTVisitor<FuncInfoCollector> {
    CheckerContext &C;
    llvm::DenseMap<const LabelDecl *, const LabelStmt *> LabelMap;
    llvm::SmallVector<const GotoStmt *, 16> Gotos;
    llvm::SmallPtrSet<const FieldDecl*, 16> LocallyAllocFields;
    llvm::DenseMap<const FieldDecl*, SourceLocation> FirstAllocLoc;

    FuncInfoCollector(CheckerContext &Ctx) : C(Ctx) {}

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

      const auto *ME = dyn_cast<MemberExpr>(LHS);
      const auto *CE = dyn_cast<CallExpr>(RHS);
      if (!ME || !CE)
        return true;

      // If RHS call looks like an allocator, record the assigned field and earliest loc.
      if (callExprLooksLikeAllocator(CE, C)) {
        if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          const FieldDecl *CanonFD = FD->getCanonicalDecl();
          LocallyAllocFields.insert(CanonFD);
          SourceLocation CurLoc = BO->getBeginLoc();
          auto It = FirstAllocLoc.find(CanonFD);
          if (It == FirstAllocLoc.end()) {
            FirstAllocLoc[CanonFD] = CurLoc;
          } else {
            const SourceManager &SM = C.getSourceManager();
            // Keep the earliest source location in TU order.
            if (SM.isBeforeInTranslationUnit(CurLoc, It->second))
              It->second = CurLoc;
          }
        }
      }
      return true;
    }

    // Heuristic allocator detection for CallExpr using source text/Callee name.
    static bool callExprLooksLikeAllocator(const CallExpr *CE, CheckerContext &C) {
      if (!CE)
        return false;

      static const char *AllocNames[] = {
          "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
          "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
          "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
      };

      // Prefer direct callee name if available.
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
  };

  const FunctionDecl *getCurrentFunction(const CheckerContext &C) const {
    const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return D;
  }

  void buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const;

  bool isAllocatorCall(const CallEvent &Call, CheckerContext &C) const;
  bool isFreeLikeCall(const CallEvent &Call, CheckerContext &C) const;

  // Returns true if the reported scenario is a false positive and should be suppressed.
  bool isFalsePositive(const MemberExpr *FreedME, const CallEvent &Call,
                       const LabelStmt *EnclosingLabel, CheckerContext &C) const;

  // Gating heuristic: return the ParmVarDecl if the base of a MemberExpr resolves directly to a function parameter.
  const ParmVarDecl *getDirectBaseParam(const Expr *BaseE) const;

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
  FuncLocallyAllocFields[FD] = std::move(Collector.LocallyAllocFields);
  FuncLabelGotos[FD] = std::move(LabelToGotos);
  // Store earliest allocator-assignment locations for fields.
  llvm::DenseMap<const FieldDecl*, SourceLocation> Earliest;
  for (const auto &P : Collector.FirstAllocLoc) {
    Earliest[P.first->getCanonicalDecl()] = P.second;
  }
  FuncFieldFirstAllocLoc[FD] = std::move(Earliest);
}

bool SAGenTestChecker::isAllocatorCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  static const char *Names[] = {
      "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
      "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
      "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
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
  // Build per-function metadata (labels and locally-allocated fields).
  buildPerFunctionInfo(FD, C);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Clean per-function metadata.
  FuncLabelIncoming.erase(FD);
  FuncLocallyAllocFields.erase(FD);
  FuncLabelGotos.erase(FD);
  FuncFieldFirstAllocLoc.erase(FD);
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

bool SAGenTestChecker::isFalsePositive(const MemberExpr *FreedME,
                                       const CallEvent &Call,
                                       const LabelStmt *EnclosingLabel,
                                       CheckerContext &C) const {
  // 1) If the argument is definitely the literal NULL at this point, kfree(NULL) is a no-op.
  SVal ArgVal = C.getSVal(Call.getArgExpr(0));
  if (ArgVal.isZeroConstant())
    return true;

  // 2) If this function path-sensitively owns the region (or its base), don't warn on this path.
  const MemRegion *FreedReg = getMemRegionFromExpr(Call.getArgExpr(0), C);
  if (FreedReg) {
    const MemRegion *Base = FreedReg->getBaseRegion();
    ProgramStateRef State = C.getState();
    if (State->contains<OwnedRegionSet>(FreedReg) ||
        (Base && State->contains<OwnedRegionSet>(Base))) {
      return true;
    }
  }

  // 3) If all incoming gotos to this label lexically occur after the earliest allocator
  //    assignment to this field in the same function, then the shared label is safe.
  const FunctionDecl *FD = getCurrentFunction(C);
  if (FD && FreedME) {
    const FieldDecl *FreedFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (FreedFD) {
      const FieldDecl *CanonFD = FreedFD->getCanonicalDecl();

      auto AllocItF = FuncFieldFirstAllocLoc.find(FD);
      auto GotoItF  = FuncLabelGotos.find(FD);
      if (AllocItF != FuncFieldFirstAllocLoc.end() &&
          GotoItF  != FuncLabelGotos.end()) {
        auto AllocIt = AllocItF->second.find(CanonFD);
        auto GLabelIt = GotoItF->second.find(EnclosingLabel);
        if (AllocIt != AllocItF->second.end() &&
            GLabelIt != GotoItF->second.end()) {
          SourceLocation AllocLoc = AllocIt->second;
          const auto &Gotos = GLabelIt->second;
          if (!Gotos.empty()) {
            const SourceManager &SM = C.getSourceManager();
            bool AnyBefore = false;
            for (const GotoStmt *GS : Gotos) {
              SourceLocation GLoc = GS->getGotoLoc();
              // If a goto appears before the allocator assignment, there exists
              // a path to the label prior to ownership -> potential bug.
              if (SM.isBeforeInTranslationUnit(GLoc, AllocLoc)) {
                AnyBefore = true;
                break;
              }
            }
            if (!AnyBefore) {
              // All incoming gotos occur after allocator assignment to this field.
              // The shared label free is consistent with local ownership.
              return true;
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
  if (!isFreeLikeCall(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return;

  // Only consider freeing a struct/union field like mt->fc.
  const Expr *Stripped = ArgE->IgnoreParenImpCasts();
  const auto *FreedME = dyn_cast<MemberExpr>(Stripped);
  if (!FreedME)
    return;

  // New gating: Only warn when the freed field belongs directly to a function parameter.
  // This matches the target buggy pattern (e.g., mt->fc) and suppresses common cleanup of local/private state (e.g., priv->...).
  const Expr *BaseE = FreedME->getBase();
  const ParmVarDecl *BaseParam = getDirectBaseParam(BaseE);
  if (!BaseParam)
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
  if (Count < 2)
    return;

  // Suppress known false positives.
  if (isFalsePositive(FreedME, Call, EnclosingLabel, C))
    return;

  reportFreeUnownedInSharedLabel(Call, C);
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
