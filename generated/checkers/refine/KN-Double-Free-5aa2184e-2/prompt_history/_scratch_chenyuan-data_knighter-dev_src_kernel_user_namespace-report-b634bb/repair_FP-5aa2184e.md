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

File:| kernel/user_namespace.c
---|---
Warning:| line 1100, column 3
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


228   | void __put_user_ns(struct user_namespace *ns)
229   | {
230   | 	schedule_work(&ns->work);
231   | }
232   | EXPORT_SYMBOL(__put_user_ns);
233   |
234   | /*
235   |  * struct idmap_key - holds the information necessary to find an idmapping in a
236   |  * sorted idmap array. It is passed to cmp_map_id() as first argument.
237   |  */
238   | struct idmap_key {
239   | 	bool map_up; /* true  -> id from kid; false -> kid from id */
240   | 	u32 id; /* id to find */
241   | 	u32 count; /* == 0 unless used with map_id_range_down() */
242   | };
243   |
244   | /*
245   |  * cmp_map_id - Function to be passed to bsearch() to find the requested
246   |  * idmapping. Expects struct idmap_key to be passed via @k.
247   |  */
248   | static int cmp_map_id(const void *k, const void *e)
249   | {
250   | 	u32 first, last, id2;
251   |  const struct idmap_key *key = k;
252   |  const struct uid_gid_extent *el = e;
253   |
254   | 	id2 = key->id + key->count - 1;
255   |
256   |  /* handle map_id_{down,up}() */
257   |  if (key->map_up)
258   | 		first = el->lower_first;
259   |  else
260   | 		first = el->first;
261   |
262   | 	last = first + el->count - 1;
263   |
264   |  if (key->id >= first && key->id <= last &&
265   | 	    (id2 >= first && id2 <= last))
266   |  return 0;
267   |
268   |  if (key->id < first || id2 < first)
269   |  return -1;
270   |
271   |  return 1;
272   | }
273   |
274   | /*
275   |  * map_id_range_down_max - Find idmap via binary search in ordered idmap array.
276   |  * Can only be called if number of mappings exceeds UID_GID_MAP_MAX_BASE_EXTENTS.
277   |  */
278   | static struct uid_gid_extent *
279   | map_id_range_down_max(unsigned extents, struct uid_gid_map *map, u32 id, u32 count)
280   | {
281   |  struct idmap_key key;
282   |
283   | 	key.map_up = false;
284   | 	key.count = count;
285   | 	key.id = id;
286   |
287   |  return bsearch(&key, map->forward, extents,
288   |  sizeof(struct uid_gid_extent), cmp_map_id);
289   | }
290   |
291   | /*
292   |  * map_id_range_down_base - Find idmap via binary search in static extent array.
293   |  * Can only be called if number of mappings is equal or less than
294   |  * UID_GID_MAP_MAX_BASE_EXTENTS.
295   |  */
296   | static struct uid_gid_extent *
297   | map_id_range_down_base(unsigned extents, struct uid_gid_map *map, u32 id, u32 count)
298   | {
299   |  unsigned idx;
300   | 	u32 first, last, id2;
301   |
302   | 	id2 = id + count - 1;
303   |
304   |  /* Find the matching extent */
305   |  for (idx = 0; idx < extents; idx++) {
306   | 		first = map->extent[idx].first;
307   | 		last = first + map->extent[idx].count - 1;
308   |  if (id >= first && id <= last &&
309   | 		    (id2 >= first && id2 <= last))
310   |  return &map->extent[idx];
311   | 	}
312   |  return NULL;
313   | }
314   |
315   | static u32 map_id_range_down(struct uid_gid_map *map, u32 id, u32 count)
316   | {
317   |  struct uid_gid_extent *extent;
318   |  unsigned extents = map->nr_extents;
319   |  smp_rmb();
320   |
321   |  if (extents <= UID_GID_MAP_MAX_BASE_EXTENTS)
322   | 		extent = map_id_range_down_base(extents, map, id, count);
323   |  else
324   | 		extent = map_id_range_down_max(extents, map, id, count);
325   |
326   |  /* Map the id or note failure */
327   |  if (extent)
328   | 		id = (id - extent->first) + extent->lower_first;
329   |  else
330   | 		id = (u32) -1;
331   |
332   |  return id;
333   | }
334   |
335   | u32 map_id_down(struct uid_gid_map *map, u32 id)
336   | {
337   |  return map_id_range_down(map, id, 1);
338   | }
339   |
340   | /*
341   |  * map_id_up_base - Find idmap via binary search in static extent array.
342   |  * Can only be called if number of mappings is equal or less than
343   |  * UID_GID_MAP_MAX_BASE_EXTENTS.
344   |  */
345   | static struct uid_gid_extent *
346   | map_id_up_base(unsigned extents, struct uid_gid_map *map, u32 id)
347   | {
348   |  unsigned idx;
349   | 	u32 first, last;
350   |
351   |  /* Find the matching extent */
352   |  for (idx = 0; idx < extents; idx++) {
353   | 		first = map->extent[idx].lower_first;
354   | 		last = first + map->extent[idx].count - 1;
355   |  if (id >= first && id <= last)
356   |  return &map->extent[idx];
357   | 	}
358   |  return NULL;
359   | }
360   |
361   | /*
362   |  * map_id_up_max - Find idmap via binary search in ordered idmap array.
873   |  * @new_map: requested idmap
874   |  *
875   |  * If a process requests mapping parent uid 0 into the new ns, verify that the
876   |  * process writing the map had the CAP_SETFCAP capability as the target process
877   |  * will be able to write fscaps that are valid in ancestor user namespaces.
878   |  *
879   |  * Return: true if the mapping is allowed, false if not.
880   |  */
881   | static bool verify_root_map(const struct file *file,
882   |  struct user_namespace *map_ns,
883   |  struct uid_gid_map *new_map)
884   | {
885   |  int idx;
886   |  const struct user_namespace *file_ns = file->f_cred->user_ns;
887   |  struct uid_gid_extent *extent0 = NULL;
888   |
889   |  for (idx = 0; idx < new_map->nr_extents; idx++) {
890   |  if (new_map->nr_extents <= UID_GID_MAP_MAX_BASE_EXTENTS)
891   | 			extent0 = &new_map->extent[idx];
892   |  else
893   | 			extent0 = &new_map->forward[idx];
894   |  if (extent0->lower_first == 0)
895   |  break;
896   |
897   | 		extent0 = NULL;
898   | 	}
899   |
900   |  if (!extent0)
901   |  return true;
902   |
903   |  if (map_ns == file_ns) {
904   |  /* The process unshared its ns and is writing to its own
905   |  * /proc/self/uid_map.  User already has full capabilites in
906   |  * the new namespace.  Verify that the parent had CAP_SETFCAP
907   |  * when it unshared.
908   |  * */
909   |  if (!file_ns->parent_could_setfcap)
910   |  return false;
911   | 	} else {
912   |  /* Process p1 is writing to uid_map of p2, who is in a child
913   |  * user namespace to p1's.  Verify that the opener of the map
914   |  * file has CAP_SETFCAP against the parent of the new map
915   |  * namespace */
916   |  if (!file_ns_capable(file, map_ns->parent, CAP_SETFCAP))
917   |  return false;
918   | 	}
919   |
920   |  return true;
921   | }
922   |
923   | static ssize_t map_write(struct file *file, const char __user *buf,
924   | 			 size_t count, loff_t *ppos,
925   |  int cap_setid,
926   |  struct uid_gid_map *map,
927   |  struct uid_gid_map *parent_map)
928   | {
929   |  struct seq_file *seq = file->private_data;
930   |  struct user_namespace *map_ns = seq->private;
931   |  struct uid_gid_map new_map;
932   |  unsigned idx;
933   |  struct uid_gid_extent extent;
934   |  char *kbuf, *pos, *next_line;
935   | 	ssize_t ret;
936   |
937   |  /* Only allow < page size writes at the beginning of the file */
938   |  if ((*ppos != 0) || (count >= PAGE_SIZE))
    4←Assuming the condition is false→
    5←Assuming the condition is false→
    6←Taking false branch→
939   |  return -EINVAL;
940   |
941   |  /* Slurp in the user data */
942   |  kbuf = memdup_user_nul(buf, count);
943   |  if (IS_ERR(kbuf))
    7←Taking false branch→
944   |  return PTR_ERR(kbuf);
945   |
946   |  /*
947   |  * The userns_state_mutex serializes all writes to any given map.
948   |  *
949   |  * Any map is only ever written once.
950   |  *
951   |  * An id map fits within 1 cache line on most architectures.
952   |  *
953   |  * On read nothing needs to be done unless you are on an
954   |  * architecture with a crazy cache coherency model like alpha.
955   |  *
956   |  * There is a one time data dependency between reading the
957   |  * count of the extents and the values of the extents.  The
958   |  * desired behavior is to see the values of the extents that
959   |  * were written before the count of the extents.
960   |  *
961   |  * To achieve this smp_wmb() is used on guarantee the write
962   |  * order and smp_rmb() is guaranteed that we don't have crazy
963   |  * architectures returning stale data.
964   |  */
965   |  mutex_lock(&userns_state_mutex);
966   |
967   |  memset(&new_map, 0, sizeof(struct uid_gid_map));
968   |
969   | 	ret = -EPERM;
970   |  /* Only allow one successful write to the map */
971   |  if (map->nr_extents != 0)
    8←Assuming field 'nr_extents' is equal to 0→
972   |  goto out;
973   |
974   |  /*
975   |  * Adjusting namespace settings requires capabilities on the target.
976   |  */
977   |  if (cap_valid(cap_setid) && !file_ns_capable(file, map_ns, CAP_SYS_ADMIN))
    9←Taking false branch→
978   |  goto out;
979   |
980   |  /* Parse the user data */
981   |  ret = -EINVAL;
982   | 	pos = kbuf;
983   |  for (; pos; pos = next_line) {
    10←Loop condition is false. Execution continues on line 1042→
984   |
985   |  /* Find the end of line and ensure I don't look past it */
986   | 		next_line = strchr(pos, '\n');
987   |  if (next_line) {
988   | 			*next_line = '\0';
989   | 			next_line++;
990   |  if (*next_line == '\0')
991   | 				next_line = NULL;
992   | 		}
993   |
994   | 		pos = skip_spaces(pos);
995   | 		extent.first = simple_strtoul(pos, &pos, 10);
996   |  if (!isspace(*pos))
997   |  goto out;
998   |
999   | 		pos = skip_spaces(pos);
1000  | 		extent.lower_first = simple_strtoul(pos, &pos, 10);
1001  |  if (!isspace(*pos))
1002  |  goto out;
1003  |
1004  | 		pos = skip_spaces(pos);
1005  | 		extent.count = simple_strtoul(pos, &pos, 10);
1006  |  if (*pos && !isspace(*pos))
1007  |  goto out;
1008  |
1009  |  /* Verify there is not trailing junk on the line */
1010  | 		pos = skip_spaces(pos);
1011  |  if (*pos != '\0')
1012  |  goto out;
1013  |
1014  |  /* Verify we have been given valid starting values */
1015  |  if ((extent.first == (u32) -1) ||
1016  | 		    (extent.lower_first == (u32) -1))
1017  |  goto out;
1018  |
1019  |  /* Verify count is not zero and does not cause the
1020  |  * extent to wrap
1021  |  */
1022  |  if ((extent.first + extent.count) <= extent.first)
1023  |  goto out;
1024  |  if ((extent.lower_first + extent.count) <=
1025  | 		     extent.lower_first)
1026  |  goto out;
1027  |
1028  |  /* Do the ranges in extent overlap any previous extents? */
1029  |  if (mappings_overlap(&new_map, &extent))
1030  |  goto out;
1031  |
1032  |  if ((new_map.nr_extents + 1) == UID_GID_MAP_MAX_EXTENTS &&
1033  | 		    (next_line != NULL))
1034  |  goto out;
1035  |
1036  | 		ret = insert_extent(&new_map, &extent);
1037  |  if (ret < 0)
1038  |  goto out;
1039  | 		ret = -EINVAL;
1040  | 	}
1041  |  /* Be very certain the new map actually exists */
1042  |  if (new_map.nr_extents == 0)
    11←Assuming field 'nr_extents' is not equal to 0→
    12←Taking false branch→
1043  |  goto out;
1044  |
1045  |  ret = -EPERM;
1046  |  /* Validate the user is allowed to use user id's mapped to. */
1047  |  if (!new_idmap_permitted(file, map_ns, cap_setid, &new_map))
    13←Taking false branch→
1048  |  goto out;
1049  |
1050  |  ret = -EPERM;
1051  |  /* Map the lower ids from the parent user namespace to the
1052  |  * kernel global id space.
1053  |  */
1054  |  for (idx = 0; idx13.1'idx' is < field 'nr_extents' < new_map.nr_extents; idx++) {
    14←Loop condition is true.  Entering loop body→
1055  |  struct uid_gid_extent *e;
1056  | 		u32 lower_first;
1057  |
1058  |  if (new_map.nr_extents <= UID_GID_MAP_MAX_BASE_EXTENTS)
    15←Assuming field 'nr_extents' is > UID_GID_MAP_MAX_BASE_EXTENTS→
    16←Taking false branch→
1059  | 			e = &new_map.extent[idx];
1060  |  else
1061  |  e = &new_map.forward[idx];
1062  |
1063  |  lower_first = map_id_range_down(parent_map,
1064  | 						e->lower_first,
1065  | 						e->count);
1066  |
1067  |  /* Fail if we can not map the specified extent to
1068  |  * the kernel global id space.
1069  |  */
1070  |  if (lower_first == (u32) -1)
    17←Taking true branch→
1071  |  goto out;
1072  |
1073  | 		e->lower_first = lower_first;
1074  | 	}
1075  |
1076  |  /*
1077  |  * If we want to use binary search for lookup, this clones the extent
1078  |  * array and sorts both copies.
1079  |  */
1080  | 	ret = sort_idmaps(&new_map);
1081  |  if (ret < 0)
1082  |  goto out;
1083  |
1084  |  /* Install the map */
1085  |  if (new_map.nr_extents <= UID_GID_MAP_MAX_BASE_EXTENTS) {
1086  |  memcpy(map->extent, new_map.extent,
1087  |  new_map.nr_extents * sizeof(new_map.extent[0]));
1088  | 	} else {
1089  | 		map->forward = new_map.forward;
1090  | 		map->reverse = new_map.reverse;
1091  | 	}
1092  |  smp_wmb();
1093  | 	map->nr_extents = new_map.nr_extents;
1094  |
1095  | 	*ppos = count;
1096  | 	ret = count;
1097  | out:
1098  |  if (ret17.1'ret' is < 0 < 0 && new_map.nr_extents17.2Field 'nr_extents' is > UID_GID_MAP_MAX_BASE_EXTENTS > UID_GID_MAP_MAX_BASE_EXTENTS) {
    18←Taking true branch→
1099  |  kfree(new_map.forward);
1100  |  kfree(new_map.reverse);
    19←Freeing unowned field in shared error label; possible double free
1101  | 		map->forward = NULL;
1102  | 		map->reverse = NULL;
1103  | 		map->nr_extents = 0;
1104  | 	}
1105  |
1106  | 	mutex_unlock(&userns_state_mutex);
1107  | 	kfree(kbuf);
1108  |  return ret;
1109  | }
1110  |
1111  | ssize_t proc_uid_map_write(struct file *file, const char __user *buf,
1112  | 			   size_t size, loff_t *ppos)
1113  | {
1114  |  struct seq_file *seq = file->private_data;
1115  |  struct user_namespace *ns = seq->private;
1116  |  struct user_namespace *seq_ns = seq_user_ns(seq);
1117  |
1118  |  if (!ns->parent)
1119  |  return -EPERM;
1120  |
1121  |  if ((seq_ns != ns) && (seq_ns != ns->parent))
1122  |  return -EPERM;
1123  |
1124  |  return map_write(file, buf, size, ppos, CAP_SETUID,
1125  | 			 &ns->uid_map, &ns->parent->uid_map);
1126  | }
1127  |
1128  | ssize_t proc_gid_map_write(struct file *file, const char __user *buf,
1129  | 			   size_t size, loff_t *ppos)
1130  | {
1131  |  struct seq_file *seq = file->private_data;
1132  |  struct user_namespace *ns = seq->private;
1133  |  struct user_namespace *seq_ns = seq_user_ns(seq);
1134  |
1135  |  if (!ns->parent)
1136  |  return -EPERM;
1137  |
1138  |  if ((seq_ns != ns) && (seq_ns != ns->parent))
1139  |  return -EPERM;
1140  |
1141  |  return map_write(file, buf, size, ppos, CAP_SETGID,
1142  | 			 &ns->gid_map, &ns->parent->gid_map);
1143  | }
1144  |
1145  | ssize_t proc_projid_map_write(struct file *file, const char __user *buf,
1146  | 			      size_t size, loff_t *ppos)
1147  | {
1148  |  struct seq_file *seq = file->private_data;
1149  |  struct user_namespace *ns = seq->private;
1150  |  struct user_namespace *seq_ns = seq_user_ns(seq);
1151  |
1152  |  if (!ns->parent)
    1Assuming field 'parent' is non-null→
1153  |  return -EPERM;
1154  |
1155  |  if ((seq_ns != ns) && (seq_ns != ns->parent))
    2←Assuming 'seq_ns' is equal to 'ns'→
1156  |  return -EPERM;
1157  |
1158  |  /* Anyone can set any valid project id no capability needed */
1159  |  return map_write(file, buf, size, ppos, -1,
    3←Calling 'map_write'→
1160  |  &ns->projid_map, &ns->parent->projid_map);
1161  | }
1162  |
1163  | static bool new_idmap_permitted(const struct file *file,
1164  |  struct user_namespace *ns, int cap_setid,
1165  |  struct uid_gid_map *new_map)
1166  | {
1167  |  const struct cred *cred = file->f_cred;
1168  |
1169  |  if (cap_setid == CAP_SETUID && !verify_root_map(file, ns, new_map))
1170  |  return false;
1171  |
1172  |  /* Don't allow mappings that would allow anything that wouldn't
1173  |  * be allowed without the establishment of unprivileged mappings.
1174  |  */
1175  |  if ((new_map->nr_extents == 1) && (new_map->extent[0].count == 1) &&
1176  | 	    uid_eq(ns->owner, cred->euid)) {
1177  | 		u32 id = new_map->extent[0].lower_first;
1178  |  if (cap_setid == CAP_SETUID) {
1179  | 			kuid_t uid = make_kuid(ns->parent, id);
1180  |  if (uid_eq(uid, cred->euid))
1181  |  return true;
1182  | 		} else if (cap_setid == CAP_SETGID) {
1183  | 			kgid_t gid = make_kgid(ns->parent, id);
1184  |  if (!(ns->flags & USERNS_SETGROUPS_ALLOWED) &&
1185  | 			    gid_eq(gid, cred->egid))
1186  |  return true;
1187  | 		}
1188  | 	}
1189  |
1190  |  /* Allow anyone to set a mapping that doesn't require privilege */
1191  |  if (!cap_valid(cap_setid))
1192  |  return true;
1193  |
1194  |  /* Allow the specified ids if we have the appropriate capability
1195  |  * (CAP_SETUID or CAP_SETGID) over the parent user namespace.
1196  |  * And the opener of the id file also has the appropriate capability.
1197  |  */
1198  |  if (ns_capable(ns->parent, cap_setid) &&
1199  | 	    file_ns_capable(file, ns->parent, cap_setid))
1200  |  return true;
1201  |
1202  |  return false;
1203  | }
1204  |
1205  | int proc_setgroups_show(struct seq_file *seq, void *v)
1206  | {
1207  |  struct user_namespace *ns = seq->private;
1208  |  unsigned long userns_flags = READ_ONCE(ns->flags);
1209  |
1210  | 	seq_printf(seq, "%s\n",
1211  | 		   (userns_flags & USERNS_SETGROUPS_ALLOWED) ?
1212  |  "allow" : "deny");
1213  |  return 0;
1214  | }
1215  |
1216  | ssize_t proc_setgroups_write(struct file *file, const char __user *buf,
1217  | 			     size_t count, loff_t *ppos)
1218  | {
1219  |  struct seq_file *seq = file->private_data;
1220  |  struct user_namespace *ns = seq->private;
1221  |  char kbuf[8], *pos;
1222  | 	bool setgroups_allowed;

Analysis:
- Decision: NotABug
- Reason: The reported cleanup in map_write() does not match the target bug pattern. The target pattern involves an unconditional shared error path freeing memory that may be callee-managed and already freed (leading to a double free). Here:
  - new_map is a local struct, zero-initialized (forward/reverse start as NULL).
  - Memory for new_map.forward/new_map.reverse is conditionally allocated by sort_idmaps() only when new_map.nr_extents > UID_GID_MAP_MAX_BASE_EXTENTS.
  - On error, the out label conditionally frees new_map.forward/reverse only when nr_extents exceeds the base threshold. kfree(NULL) is safe, so freeing when they were never allocated is harmless.
  - Ownership remains with this function until the “Install the map” step; on success, pointers are transferred to map->forward/reverse and the error-path free is skipped. On failure, it is the caller’s responsibility to free any partial allocations. There is no evidence of another free of these pointers on the same path, so no double free arises.
  - This does not exhibit the “callee already freed” hazard described in the target bug pattern, nor is the cleanup unconditional.

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
