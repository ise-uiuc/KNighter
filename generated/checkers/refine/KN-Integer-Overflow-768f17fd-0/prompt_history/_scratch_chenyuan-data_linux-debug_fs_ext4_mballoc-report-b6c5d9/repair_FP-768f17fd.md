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

File:| /scratch/chenyuan-data/linux-debug/fs/ext4/mballoc.c
---|---
Warning:| line 6520, column 4
Shift done in 32-bit, widened after; cast left operand to 64-bit before <<

### Annotated Source Code


6339  | 		}
6340  | 	}
6341  |
6342  | 	rb_link_node(new_node, parent, n);
6343  | 	rb_insert_color(new_node, &db->bb_free_root);
6344  |
6345  |  /* Now try to see the extent can be merged to left and right */
6346  | 	node = rb_prev(new_node);
6347  |  if (node) {
6348  | 		entry = rb_entry(node, struct ext4_free_data, efd_node);
6349  | 		ext4_try_merge_freed_extent(sbi, entry, new_entry,
6350  | 					    &(db->bb_free_root));
6351  | 	}
6352  |
6353  | 	node = rb_next(new_node);
6354  |  if (node) {
6355  | 		entry = rb_entry(node, struct ext4_free_data, efd_node);
6356  | 		ext4_try_merge_freed_extent(sbi, entry, new_entry,
6357  | 					    &(db->bb_free_root));
6358  | 	}
6359  |
6360  | 	spin_lock(&sbi->s_md_lock);
6361  | 	list_add_tail(&new_entry->efd_list, &sbi->s_freed_data_list[new_entry->efd_tid & 1]);
6362  | 	sbi->s_mb_free_pending += clusters;
6363  | 	spin_unlock(&sbi->s_md_lock);
6364  | }
6365  |
6366  | static void ext4_free_blocks_simple(struct inode *inode, ext4_fsblk_t block,
6367  |  unsigned long count)
6368  | {
6369  |  struct super_block *sb = inode->i_sb;
6370  | 	ext4_group_t group;
6371  | 	ext4_grpblk_t blkoff;
6372  |
6373  | 	ext4_get_group_no_and_offset(sb, block, &group, &blkoff);
6374  | 	ext4_mb_mark_context(NULL, sb, false, group, blkoff, count,
6375  |  EXT4_MB_BITMAP_MARKED_CHECK |
6376  |  EXT4_MB_SYNC_UPDATE,
6377  |  NULL);
6378  | }
6379  |
6380  | /**
6381  |  * ext4_mb_clear_bb() -- helper function for freeing blocks.
6382  |  *			Used by ext4_free_blocks()
6383  |  * @handle:		handle for this transaction
6384  |  * @inode:		inode
6385  |  * @block:		starting physical block to be freed
6386  |  * @count:		number of blocks to be freed
6387  |  * @flags:		flags used by ext4_free_blocks
6388  |  */
6389  | static void ext4_mb_clear_bb(handle_t *handle, struct inode *inode,
6390  | 			       ext4_fsblk_t block, unsigned long count,
6391  |  int flags)
6392  | {
6393  |  struct super_block *sb = inode->i_sb;
6394  |  struct ext4_group_info *grp;
6395  |  unsigned int overflow;
6396  | 	ext4_grpblk_t bit;
6397  | 	ext4_group_t block_group;
6398  |  struct ext4_sb_info *sbi;
6399  |  struct ext4_buddy e4b;
6400  |  unsigned int count_clusters;
6401  |  int err = 0;
6402  |  int mark_flags = 0;
6403  | 	ext4_grpblk_t changed;
6404  |
6405  | 	sbi = EXT4_SB(sb);
6406  |
6407  |  if (!(flags & EXT4_FREE_BLOCKS_VALIDATED) &&
    19←Assuming the condition is true→
    21←Taking false branch→
6408  |  !ext4_inode_block_valid(inode, block, count)) {
    20←Assuming the condition is false→
6409  |  ext4_error(sb, "Freeing blocks in system zone - "
6410  |  "Block = %llu, count = %lu", block, count);
6411  |  /* err = 0. ext4_std_error should be a no op */
6412  |  goto error_out;
6413  | 	}
6414  |  flags |= EXT4_FREE_BLOCKS_VALIDATED;
6415  |
6416  | do_more:
6417  |  overflow = 0;
6418  |  ext4_get_group_no_and_offset(sb, block, &block_group, &bit);
6419  |
6420  | 	grp = ext4_get_group_info(sb, block_group);
6421  |  if (unlikely(!grp || EXT4_MB_GRP_BBITMAP_CORRUPT(grp)))
    22←Assuming 'grp' is non-null→
    23←Assuming the condition is false→
    24←Taking false branch→
6422  |  return;
6423  |
6424  |  /*
6425  |  * Check to see if we are freeing blocks across a group
6426  |  * boundary.
6427  |  */
6428  |  if (EXT4_C2B(sbi, bit) + count > EXT4_BLOCKS_PER_GROUP(sb)) {
    25←Assuming right operand of bit shift is less than 32→
    26←Assuming the condition is false→
    27←Taking false branch→
6429  | 		overflow = EXT4_C2B(sbi, bit) + count -
6430  |  EXT4_BLOCKS_PER_GROUP(sb);
6431  | 		count -= overflow;
6432  |  /* The range changed so it's no longer validated */
6433  | 		flags &= ~EXT4_FREE_BLOCKS_VALIDATED;
6434  | 	}
6435  |  count_clusters = EXT4_NUM_B2C(sbi, count);
6436  | 	trace_ext4_mballoc_free(sb, inode, block_group, bit, count_clusters);
6437  |
6438  |  /* __GFP_NOFAIL: retry infinitely, ignore TIF_MEMDIE and memcg limit. */
6439  | 	err = ext4_mb_load_buddy_gfp(sb, block_group, &e4b,
6440  |  GFP_NOFS|__GFP_NOFAIL);
6441  |  if (err)
    28←Assuming 'err' is 0→
6442  |  goto error_out;
6443  |
6444  |  if (!(flags & EXT4_FREE_BLOCKS_VALIDATED) &&
    29←Assuming the condition is true→
    31←Taking false branch→
6445  |  !ext4_inode_block_valid(inode, block, count)) {
    30←Assuming the condition is false→
6446  |  ext4_error(sb, "Freeing blocks in system zone - "
6447  |  "Block = %llu, count = %lu", block, count);
6448  |  /* err = 0. ext4_std_error should be a no op */
6449  |  goto error_clean;
6450  | 	}
6451  |
6452  | #ifdef AGGRESSIVE_CHECK
6453  | 	mark_flags |= EXT4_MB_BITMAP_MARKED_CHECK;
6454  | #endif
6455  |  err = ext4_mb_mark_context(handle, sb, false, block_group, bit,
6456  | 				   count_clusters, mark_flags, &changed);
6457  |
6458  |
6459  |  if (err && changed == 0)
    32←Assuming 'err' is 0→
6460  |  goto error_clean;
6461  |
6462  | #ifdef AGGRESSIVE_CHECK
6463  |  BUG_ON(changed != count_clusters);
6464  | #endif
6465  |
6466  |  /*
6467  |  * We need to make sure we don't reuse the freed block until after the
6468  |  * transaction is committed. We make an exception if the inode is to be
6469  |  * written in writeback mode since writeback mode has weak data
6470  |  * consistency guarantees.
6471  |  */
6472  |  if (ext4_handle_valid(handle) &&
6473  | 	    ((flags & EXT4_FREE_BLOCKS_METADATA) ||
6474  | 	     !ext4_should_writeback_data(inode))) {
6475  |  struct ext4_free_data *new_entry;
6476  |  /*
6477  |  * We use __GFP_NOFAIL because ext4_free_blocks() is not allowed
6478  |  * to fail.
6479  |  */
6480  | 		new_entry = kmem_cache_alloc(ext4_free_data_cachep,
6481  |  GFP_NOFS|__GFP_NOFAIL);
6482  | 		new_entry->efd_start_cluster = bit;
6483  | 		new_entry->efd_group = block_group;
6484  | 		new_entry->efd_count = count_clusters;
6485  | 		new_entry->efd_tid = handle->h_transaction->t_tid;
6486  |
6487  | 		ext4_lock_group(sb, block_group);
6488  | 		ext4_mb_free_metadata(handle, &e4b, new_entry);
6489  | 	} else {
6490  |  if (test_opt(sb, DISCARD)) {
    33←Assuming the condition is false→
    34←Taking false branch→
6491  | 			err = ext4_issue_discard(sb, block_group, bit,
6492  | 						 count_clusters);
6493  |  /*
6494  |  * Ignore EOPNOTSUPP error. This is consistent with
6495  |  * what happens when using journal.
6496  |  */
6497  |  if (err == -EOPNOTSUPP)
6498  | 				err = 0;
6499  |  if (err)
6500  |  ext4_msg(sb, KERN_WARNING, "discard request in"
6501  |  " group:%u block:%d count:%lu failed"
6502  |  " with %d", block_group, bit, count,
6503  |  err);
6504  | 		} else
6505  |  EXT4_MB_GRP_CLEAR_TRIMMED(e4b.bd_info);
6506  |
6507  |  ext4_lock_group(sb, block_group);
6508  |  mb_free_blocks(inode, &e4b, bit, count_clusters);
6509  | 	}
6510  |
6511  |  ext4_unlock_group(sb, block_group);
6512  |
6513  |  /*
6514  |  * on a bigalloc file system, defer the s_freeclusters_counter
6515  |  * update to the caller (ext4_remove_space and friends) so they
6516  |  * can determine if a cluster freed here should be rereserved
6517  |  */
6518  |  if (!(flags & EXT4_FREE_BLOCKS_RERESERVE_CLUSTER)) {
    35←Assuming the condition is true→
    36←Taking true branch→
6519  |  if (!(flags & EXT4_FREE_BLOCKS_NO_QUOT_UPDATE))
    37←Assuming the condition is true→
    38←Taking true branch→
6520  |  dquot_free_block(inode, EXT4_C2B(sbi, count_clusters));
    39←Shift done in 32-bit, widened after; cast left operand to 64-bit before <<
6521  | 		percpu_counter_add(&sbi->s_freeclusters_counter,
6522  | 				   count_clusters);
6523  | 	}
6524  |
6525  |  if (overflow && !err) {
6526  | 		block += count;
6527  | 		count = overflow;
6528  | 		ext4_mb_unload_buddy(&e4b);
6529  |  /* The range changed so it's no longer validated */
6530  | 		flags &= ~EXT4_FREE_BLOCKS_VALIDATED;
6531  |  goto do_more;
6532  | 	}
6533  |
6534  | error_clean:
6535  | 	ext4_mb_unload_buddy(&e4b);
6536  | error_out:
6537  |  ext4_std_error(sb, err);
6538  | }
6539  |
6540  | /**
6541  |  * ext4_free_blocks() -- Free given blocks and update quota
6542  |  * @handle:		handle for this transaction
6543  |  * @inode:		inode
6544  |  * @bh:			optional buffer of the block to be freed
6545  |  * @block:		starting physical block to be freed
6546  |  * @count:		number of blocks to be freed
6547  |  * @flags:		flags used by ext4_free_blocks
6548  |  */
6549  | void ext4_free_blocks(handle_t *handle, struct inode *inode,
6550  |  struct buffer_head *bh, ext4_fsblk_t block,
6551  |  unsigned long count, int flags)
6552  | {
6553  |  struct super_block *sb = inode->i_sb;
6554  |  unsigned int overflow;
6555  |  struct ext4_sb_info *sbi;
6556  |
6557  | 	sbi = EXT4_SB(sb);
6558  |
6559  |  if (bh) {
    1Assuming 'bh' is null→
    2←Taking false branch→
6560  |  if (block)
6561  |  BUG_ON(block != bh->b_blocknr);
6562  |  else
6563  | 			block = bh->b_blocknr;
6564  | 	}
6565  |
6566  |  if (sbi->s_mount_state & EXT4_FC_REPLAY) {
    3←Assuming the condition is false→
    4←Taking false branch→
6567  | 		ext4_free_blocks_simple(inode, block, EXT4_NUM_B2C(sbi, count));
6568  |  return;
6569  | 	}
6570  |
6571  |  might_sleep();
6572  |
6573  |  if (!(flags & EXT4_FREE_BLOCKS_VALIDATED) &&
    5←Assuming the condition is false→
6574  | 	    !ext4_inode_block_valid(inode, block, count)) {
6575  |  ext4_error(sb, "Freeing blocks not in datazone - "
6576  |  "block = %llu, count = %lu", block, count);
6577  |  return;
6578  | 	}
6579  |  flags |= EXT4_FREE_BLOCKS_VALIDATED;
6580  |
6581  |  ext4_debug("freeing block %llu\n", block);
    6←Taking false branch→
6582  | 	trace_ext4_free_blocks(inode, block, count, flags);
6583  |
6584  |  if (bh6.1'bh' is null && (flags & EXT4_FREE_BLOCKS_FORGET)) {
6585  |  BUG_ON(count > 1);
6586  |
6587  |  ext4_forget(handle, flags & EXT4_FREE_BLOCKS_METADATA,
6588  |  inode, bh, block);
6589  | 	}
6590  |
6591  |  /*
6592  |  * If the extent to be freed does not begin on a cluster
6593  |  * boundary, we need to deal with partial clusters at the
6594  |  * beginning and end of the extent.  Normally we will free
6595  |  * blocks at the beginning or the end unless we are explicitly
6596  |  * requested to avoid doing so.
6597  |  */
6598  |  overflow = EXT4_PBLK_COFF(sbi, block);
6599  |  if (overflow) {
    7←Assuming 'overflow' is 0→
    8←Taking false branch→
6600  |  if (flags & EXT4_FREE_BLOCKS_NOFREE_FIRST_CLUSTER) {
6601  | 			overflow = sbi->s_cluster_ratio - overflow;
6602  | 			block += overflow;
6603  |  if (count > overflow)
6604  | 				count -= overflow;
6605  |  else
6606  |  return;
6607  | 		} else {
6608  | 			block -= overflow;
6609  | 			count += overflow;
6610  | 		}
6611  |  /* The range changed so it's no longer validated */
6612  | 		flags &= ~EXT4_FREE_BLOCKS_VALIDATED;
6613  | 	}
6614  |  overflow = EXT4_LBLK_COFF(sbi, count);
6615  |  if (overflow) {
    9←Assuming 'overflow' is 0→
6616  |  if (flags & EXT4_FREE_BLOCKS_NOFREE_LAST_CLUSTER) {
6617  |  if (count > overflow)
6618  | 				count -= overflow;
6619  |  else
6620  |  return;
6621  | 		} else
6622  | 			count += sbi->s_cluster_ratio - overflow;
6623  |  /* The range changed so it's no longer validated */
6624  | 		flags &= ~EXT4_FREE_BLOCKS_VALIDATED;
6625  | 	}
6626  |
6627  |  if (!bh9.1'bh' is null && (flags & EXT4_FREE_BLOCKS_FORGET)) {
    10←Assuming the condition is true→
    11←Taking true branch→
6628  |  int i;
6629  |  int is_metadata = flags & EXT4_FREE_BLOCKS_METADATA;
6630  |
6631  |  for (i = 0; i < count; i++) {
    12←Assuming 'i' is < 'count'→
    13←Loop condition is true.  Entering loop body→
    16←Assuming 'i' is >= 'count'→
    17←Loop condition is false. Execution continues on line 6639→
6632  |  cond_resched();
6633  |  if (is_metadata)
    14←Assuming 'is_metadata' is 0→
    15←Taking false branch→
6634  | 				bh = sb_find_get_block(inode->i_sb, block + i);
6635  |  ext4_forget(handle, is_metadata, inode, bh, block + i);
6636  |  }
6637  | 	}
6638  |
6639  |  ext4_mb_clear_bb(handle, inode, block, count, flags);
    18←Calling 'ext4_mb_clear_bb'→
6640  | }
6641  |
6642  | /**
6643  |  * ext4_group_add_blocks() -- Add given blocks to an existing group
6644  |  * @handle:			handle to this transaction
6645  |  * @sb:				super block
6646  |  * @block:			start physical block to add to the block group
6647  |  * @count:			number of blocks to free
6648  |  *
6649  |  * This marks the blocks as free in the bitmap and buddy.
6650  |  */
6651  | int ext4_group_add_blocks(handle_t *handle, struct super_block *sb,
6652  | 			 ext4_fsblk_t block, unsigned long count)
6653  | {
6654  | 	ext4_group_t block_group;
6655  | 	ext4_grpblk_t bit;
6656  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
6657  |  struct ext4_buddy e4b;
6658  |  int err = 0;
6659  | 	ext4_fsblk_t first_cluster = EXT4_B2C(sbi, block);
6660  | 	ext4_fsblk_t last_cluster = EXT4_B2C(sbi, block + count - 1);
6661  |  unsigned long cluster_count = last_cluster - first_cluster + 1;
6662  | 	ext4_grpblk_t changed;
6663  |
6664  |  ext4_debug("Adding block(s) %llu-%llu\n", block, block + count - 1);
6665  |
6666  |  if (cluster_count == 0)
6667  |  return 0;
6668  |
6669  | 	ext4_get_group_no_and_offset(sb, block, &block_group, &bit);

Analysis:
- Decision: NotABug
- Reason: The warning targets a 32-bit left shift widened after the shift at dquot_free_block(inode, EXT4_C2B(sbi, count_clusters)). In ext4, EXT4_C2B is defined to operate in block-number width (ext4_fsblk_t, 64-bit) by casting before the shift, so the shift is performed in 64-bit. Even if one assumed no cast in the macro, this particular call site cannot overflow 32-bit: earlier logic ensures the free extent is confined within a single block group and aligned to full clusters (see the adjustments around lines 6591–6625 and the group-boundary check at 6428). Consequently, count_clusters = count >> s_cluster_bits with count <= EXT4_BLOCKS_PER_GROUP(sb). Since EXT4_BLOCKS_PER_GROUP(sb) is bounded by the bitmap size (typically 8 * blocksize, i.e., up to 524,288 blocks for 64k block size), EXT4_C2B(sbi, count_clusters) equals count and remains <= 524,288, well within 32-bit. Therefore, no 32-bit truncation can occur here, and the report does not match the target bug pattern nor a real bug.

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
#include "llvm/ADT/ImmutableMap.h"
#include <algorithm>
#include <cctype>
#include <optional>

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

// Track per-variable coarse upper bounds learned from assignments.
// Key: VarDecl*, Value: APSInt upper bound (unsigned).
namespace {
struct VarUpperBoundMap {};
}

namespace clang {
namespace ento {
template <>
struct ProgramStateTrait<VarUpperBoundMap>
    : public ProgramStatePartialTrait<llvm::ImmutableMap<const VarDecl *, llvm::APSInt>> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};
} // namespace ento
} // namespace clang

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

  static const Expr *peel(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  static const BinaryOperator *asShift(const Stmt *S) {
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_Shl)
        return BO;
    }
    return nullptr;
  }

  static bool isTopLevelShiftExpr(const Expr *ContainerE, const BinaryOperator *Shl) {
    if (!ContainerE || !Shl)
      return false;
    const Expr *Top = peel(ContainerE);
    return Top == static_cast<const Expr *>(Shl);
  }

  static bool constantShiftFitsInLHSWidth(const Expr *L, const Expr *R,
                                          unsigned LHSW, CheckerContext &C) {
    llvm::APSInt LHSEval, RHSEval;
    if (!EvaluateExprToInt(LHSEval, L, C))
      return false;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;

    if (LHSEval.isSigned() && LHSEval.isNegative())
      return false;

    unsigned LBits = LHSEval.getActiveBits();
    uint64_t ShiftAmt = RHSEval.getZExtValue();
    if (LBits == 0)
      return true;
    return (uint64_t)LBits + ShiftAmt <= (uint64_t)LHSW;
  }

  static bool isAnyLongType(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::Long) ||
           QT->isSpecificBuiltinType(BuiltinType::ULong);
  }

  static bool isFixed64Builtin(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::LongLong) ||
           QT->isSpecificBuiltinType(BuiltinType::ULongLong);
  }

  static bool calleeNameLooksLikeIOOrReg(StringRef Name) {
    llvm::SmallString<64> Lower(Name);
    for (char &c : Lower)
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    StringRef S(Lower);
    return S.contains("read") || S.contains("write") || S.contains("peek") ||
           S.contains("poke") || S.contains("in") || S.contains("out") ||
           S.contains("io") || S.contains("reg");
  }

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

  static bool tryGetConstShiftAmount(const Expr *R, CheckerContext &C, uint64_t &Out) {
    llvm::APSInt RHSEval;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;
    Out = RHSEval.getZExtValue();
    return true;
  }

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

  static bool isFalsePositiveContext(const Expr *WholeExpr,
                                     const BinaryOperator *Shl,
                                     QualType DestTy,
                                     CheckerContext &C,
                                     StringRef Ctx) {
    if (!isTopLevelShiftExpr(WholeExpr, Shl))
      return true;

    if (Ctx == "argument") {
      const CallExpr *CE = nullptr;
      unsigned ArgIdx = 0;
      if (findCallParentAndArgIndex(WholeExpr, C, CE, ArgIdx)) {
        const FunctionDecl *FD = CE->getDirectCallee();
        const ParmVarDecl *PVD = nullptr;
        if (FD && ArgIdx < FD->getNumParams())
          PVD = FD->getParamDecl(ArgIdx);

        if (isAnyLongType(DestTy))
          return true;

        if (PVD && paramNameLooksLikeAddrOffset(PVD))
          return true;

        if (FD) {
          if (const IdentifierInfo *ID = FD->getIdentifier()) {
            if (calleeNameLooksLikeIOOrReg(ID->getName()))
              return true;
          }
        }

        uint64_t K = 0;
        if (tryGetConstShiftAmount(Shl->getRHS(), C, K) && K <= 3)
          return true;
      }
    }

    return false;
  }

  // Extract a coarse upper bound from an assignment RHS by scanning integer literals.
  // Intended to capture patterns like min(x, CONST) where CONST is the controlling bound.
  static bool extractUpperBoundLiteralFromRHS(const Expr *RHS, CheckerContext &C,
                                              llvm::APSInt &Out) {
    if (!RHS)
      return false;

    // Walk the subtree, find the maximum integer literal value.
    llvm::APSInt MaxVal(64, true); // unsigned
    bool Found = false;

    llvm::SmallVector<const Stmt *, 16> Worklist;
    Worklist.push_back(RHS);
    while (!Worklist.empty()) {
      const Stmt *Cur = Worklist.pop_back_val();
      if (!Cur) continue;

      if (const auto *IL = dyn_cast<IntegerLiteral>(Cur)) {
        llvm::APInt V = IL->getValue();
        if (!Found || V.ugt(MaxVal))
          MaxVal = llvm::APSInt(V, /*isUnsigned=*/true);
        Found = true;
      } else if (const auto *CharL = dyn_cast<CharacterLiteral>(Cur)) {
        llvm::APInt V(64, CharL->getValue());
        if (!Found || V.ugt(MaxVal))
          MaxVal = llvm::APSInt(V, /*isUnsigned=*/true);
        Found = true;
      } else if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
        // Try to handle sizeof-like folds that may appear as integral casts.
        // We still just traverse.
        if (const Expr *SubE = UO->getSubExpr())
          Worklist.push_back(SubE);
      } else {
        for (const Stmt *Child : Cur->children())
          if (Child)
            Worklist.push_back(Child);
      }
    }

    if (Found) {
      Out = MaxVal;
      return true;
    }
    return false;
  }

  // Get a recorded per-variable upper bound from program state.
  static bool getRecordedVarUpperBound(const Expr *E, CheckerContext &C,
                                       llvm::APSInt &Out) {
    const auto *DRE = dyn_cast_or_null<DeclRefExpr>(peel(E));
    if (!DRE)
      return false;
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;

    ProgramStateRef State = C.getState();
    const llvm::APSInt *Stored = State->get<VarUpperBoundMap>(VD);
    if (!Stored)
      return false;
    Out = *Stored;
    return true;
  }

  // Compute an upper bound for an expression based on:
  // - Exact constant evaluation
  // - Recorded per-variable upper bounds
  // - Simple addition of sub-bounds
  static bool computeExprUpperBound(const Expr *E, CheckerContext &C,
                                    llvm::APSInt &Out) {
    if (!E)
      return false;
    E = peel(E);

    // Constant?
    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, E, C)) {
      if (Val.isSigned() && Val.isNegative())
        return false; // not handling negative bounds here
      Out = Val.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }

    // Variable with recorded bound?
    if (getRecordedVarUpperBound(E, C, Out))
      return true;

    // Symbolic? Try constraint manager max.
    ProgramStateRef State = C.getState();
    SVal SV = State->getSVal(E, C.getLocationContext());
    if (std::optional<nonloc::ConcreteInt> CI = SV.getAs<nonloc::ConcreteInt>()) {
      llvm::APSInt CIVal = CI->getValue();
      if (CIVal.isSigned() && CIVal.isNegative())
        return false;
      Out = CIVal.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }
    if (SymbolRef Sym = SV.getAsSymbol()) {
      if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
        llvm::APSInt M = *Max;
        if (M.isSigned() && M.isNegative())
          return false;
        Out = M.extOrTrunc(64);
        Out.setIsUnsigned(true);
        return true;
      }
    }

    // Composite expressions: try L + R for additions
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Add) {
        llvm::APSInt LUB, RUB;
        if (computeExprUpperBound(BO->getLHS(), C, LUB) &&
            computeExprUpperBound(BO->getRHS(), C, RUB)) {
          unsigned BW = std::max(LUB.getBitWidth(), RUB.getBitWidth());
          llvm::APSInt L2 = LUB.extOrTrunc(BW);
          llvm::APSInt R2 = RUB.extOrTrunc(BW);
          L2.setIsUnsigned(true);
          R2.setIsUnsigned(true);
          Out = L2 + R2;
          Out.setIsUnsigned(true);
          return true;
        }
      }
      // Other ops: give up (conservative)
    }

    return false;
  }

  // Compute maximum number of active bits an expression's value can have,
  // using constants or recorded/symbolic upper bounds.
  static bool computeExprMaxActiveBits(const Expr *E, CheckerContext &C,
                                       unsigned &OutBits) {
    if (!E)
      return false;
    E = peel(E);

    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, E, C)) {
      if (Val.isSigned() && Val.isNegative())
        return false;
      OutBits = Val.getActiveBits();
      return true;
    }

    llvm::APSInt UB;
    if (computeExprUpperBound(E, C, UB)) {
      // Active bits of the upper bound is an upper bound on the active bits.
      OutBits = UB.getActiveBits();
      return true;
    }

    return false;
  }

  // Decide if the shift is provably safe within the LHS bitwidth (e.g., 32-bit)
  // under computed upper bounds for L and R.
  static bool shiftSafeUnderUpperBounds(const Expr *L, const Expr *R,
                                        unsigned LHSW, CheckerContext &C) {
    unsigned MaxLBits = 0;
    if (!computeExprMaxActiveBits(L, C, MaxLBits))
      return false;

    llvm::APSInt RMax;
    if (!computeExprUpperBound(R, C, RMax))
      return false;

    uint64_t ShiftMax = RMax.getZExtValue();

    if (MaxLBits == 0)
      return true;

    return (uint64_t)MaxLBits + ShiftMax <= (uint64_t)LHSW;
  }
};

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

  if (!L->getType()->isIntegerType())
    return;

  unsigned LHSW = ACtx.getIntWidth(L->getType());
  if (LHSW >= 64)
    return; // LHS already wide.

  if (hasExplicitCastToWide64(L, ACtx))
    return;

  if (isFalsePositiveContext(E, Shl, DestTy, C, Ctx))
    return;

  // Constant proof: safely fits.
  if (constantShiftFitsInLHSWidth(L, R, LHSW, C))
    return;

  // New: Symbolic upper-bound proof: if we can prove the result fits in 32-bit,
  // suppress. This addresses cases like: pool_size = 1 << (PAGE_SHIFT + order),
  // where 'order' was clamped by min(..., MAX_PAGE_ORDER).
  if (shiftSafeUnderUpperBounds(L, R, LHSW, C))
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

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  // First, perform shift-to-wide analysis for assignment context.
  QualType DestTy = LHS->getType();
  analyzeAndReportShiftToWide(RHS, DestTy, C, "assignment");

  // Second, update per-variable upper bounds when possible to help suppress FPs.
  const auto *DRE = dyn_cast<DeclRefExpr>(peel(LHS));
  if (!DRE)
    return;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  llvm::APSInt BoundLit;
  if (extractUpperBoundLiteralFromRHS(RHS, C, BoundLit)) {
    // Store or update with the maximum bound seen.
    ProgramStateRef State = C.getState();
    const llvm::APSInt *Cur = State->get<VarUpperBoundMap>(VD);
    llvm::APSInt NewBound = BoundLit;
    if (Cur && Cur->ugt(NewBound))
      NewBound = *Cur;
    ProgramStateRef NewState = State->set<VarUpperBoundMap>(VD, NewBound);
    if (NewState != State)
      C.addTransition(NewState);
  }
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
