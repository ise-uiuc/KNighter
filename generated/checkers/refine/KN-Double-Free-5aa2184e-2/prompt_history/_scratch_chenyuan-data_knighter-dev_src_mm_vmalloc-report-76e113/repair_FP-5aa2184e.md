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

File:| mm/vmalloc.c
---|---
Warning:| line 3701, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


845   | struct rb_list {
846   |  struct rb_root root;
847   |  struct list_head head;
848   | 	spinlock_t lock;
849   | };
850   |
851   | /*
852   |  * A fast size storage contains VAs up to 1M size. A pool consists
853   |  * of linked between each other ready to go VAs of certain sizes.
854   |  * An index in the pool-array corresponds to number of pages + 1.
855   |  */
856   | #define MAX_VA_SIZE_PAGES 256
857   |
858   | struct vmap_pool {
859   |  struct list_head head;
860   |  unsigned long len;
861   | };
862   |
863   | /*
864   |  * An effective vmap-node logic. Users make use of nodes instead
865   |  * of a global heap. It allows to balance an access and mitigate
866   |  * contention.
867   |  */
868   | static struct vmap_node {
869   |  /* Simple size segregated storage. */
870   |  struct vmap_pool pool[MAX_VA_SIZE_PAGES];
871   | 	spinlock_t pool_lock;
872   | 	bool skip_populate;
873   |
874   |  /* Bookkeeping data of this node. */
875   |  struct rb_list busy;
876   |  struct rb_list lazy;
877   |
878   |  /*
879   |  * Ready-to-free areas.
880   |  */
881   |  struct list_head purge_list;
882   |  struct work_struct purge_work;
883   |  unsigned long nr_purged;
884   | } single;
885   |
886   | /*
887   |  * Initial setup consists of one single node, i.e. a balancing
888   |  * is fully disabled. Later on, after vmap is initialized these
889   |  * parameters are updated based on a system capacity.
890   |  */
891   | static struct vmap_node *vmap_nodes = &single;
892   | static __read_mostly unsigned int nr_vmap_nodes = 1;
893   | static __read_mostly unsigned int vmap_zone_size = 1;
894   |
895   | static inline unsigned int
896   | addr_to_node_id(unsigned long addr)
897   | {
898   |  return (addr / vmap_zone_size) % nr_vmap_nodes;
899   | }
900   |
901   | static inline struct vmap_node *
902   | addr_to_node(unsigned long addr)
903   | {
904   |  return &vmap_nodes[addr_to_node_id(addr)];
905   | }
906   |
907   | static inline struct vmap_node *
908   | id_to_node(unsigned int id)
909   | {
910   |  return &vmap_nodes[id % nr_vmap_nodes];
911   | }
912   |
913   | /*
914   |  * We use the value 0 to represent "no node", that is why
915   |  * an encoded value will be the node-id incremented by 1.
916   |  * It is always greater then 0. A valid node_id which can
917   |  * be encoded is [0:nr_vmap_nodes - 1]. If a passed node_id
918   |  * is not valid 0 is returned.
919   |  */
920   | static unsigned int
921   | encode_vn_id(unsigned int node_id)
922   | {
923   |  /* Can store U8_MAX [0:254] nodes. */
924   |  if (node_id < nr_vmap_nodes)
925   |  return (node_id + 1) << BITS_PER_BYTE;
926   |
927   |  /* Warn and no node encoded. */
928   |  WARN_ONCE(1, "Encode wrong node id (%u)\n", node_id);
929   |  return 0;
930   | }
931   |
932   | /*
933   |  * Returns an encoded node-id, the valid range is within
934   |  * [0:nr_vmap_nodes-1] values. Otherwise nr_vmap_nodes is
1263  | 		computed_size = compute_subtree_max_size(va);
1264  |  if (computed_size != va->subtree_max_size)
1265  |  pr_emerg("tree is corrupted: %lu, %lu\n",
1266  |  va_size(va), va->subtree_max_size);
1267  | 	}
1268  | }
1269  | #endif
1270  |
1271  | /*
1272  |  * This function populates subtree_max_size from bottom to upper
1273  |  * levels starting from VA point. The propagation must be done
1274  |  * when VA size is modified by changing its va_start/va_end. Or
1275  |  * in case of newly inserting of VA to the tree.
1276  |  *
1277  |  * It means that __augment_tree_propagate_from() must be called:
1278  |  * - After VA has been inserted to the tree(free path);
1279  |  * - After VA has been shrunk(allocation path);
1280  |  * - After VA has been increased(merging path).
1281  |  *
1282  |  * Please note that, it does not mean that upper parent nodes
1283  |  * and their subtree_max_size are recalculated all the time up
1284  |  * to the root node.
1285  |  *
1286  |  *       4--8
1287  |  *        /\
1288  |  *       /  \
1289  |  *      /    \
1290  |  *    2--2  8--8
1291  |  *
1292  |  * For example if we modify the node 4, shrinking it to 2, then
1293  |  * no any modification is required. If we shrink the node 2 to 1
1294  |  * its subtree_max_size is updated only, and set to 1. If we shrink
1295  |  * the node 8 to 6, then its subtree_max_size is set to 6 and parent
1296  |  * node becomes 4--6.
1297  |  */
1298  | static __always_inline void
1299  | augment_tree_propagate_from(struct vmap_area *va)
1300  | {
1301  |  /*
1302  |  * Populate the tree from bottom towards the root until
1303  |  * the calculated maximum available size of checked node
1304  |  * is equal to its current one.
1305  |  */
1306  | 	free_vmap_area_rb_augment_cb_propagate(&va->rb_node, NULL);
1307  |
1308  | #if DEBUG_AUGMENT_PROPAGATE_CHECK
1309  | 	augment_tree_propagate_check();
1310  | #endif
1311  | }
1312  |
1313  | static void
1314  | insert_vmap_area(struct vmap_area *va,
1315  |  struct rb_root *root, struct list_head *head)
1316  | {
1317  |  struct rb_node **link;
1318  |  struct rb_node *parent;
1319  |
1320  | 	link = find_va_links(va, root, NULL, &parent);
1321  |  if (link)
1322  | 		link_va(va, root, parent, link, head);
1323  | }
1324  |
1325  | static void
1326  | insert_vmap_area_augment(struct vmap_area *va,
1327  |  struct rb_node *from, struct rb_root *root,
1328  |  struct list_head *head)
1329  | {
1330  |  struct rb_node **link;
1331  |  struct rb_node *parent;
1332  |
1333  |  if (from)
1334  | 		link = find_va_links(va, NULL, from, &parent);
1335  |  else
1336  | 		link = find_va_links(va, root, NULL, &parent);
1337  |
1338  |  if (link) {
1339  | 		link_va_augment(va, root, parent, link, head);
1340  | 		augment_tree_propagate_from(va);
1341  | 	}
1342  | }
1343  |
1344  | /*
1345  |  * Merge de-allocated chunk of VA memory with previous
1346  |  * and next free blocks. If coalesce is not done a new
1347  |  * free area is inserted. If VA has been merged, it is
1348  |  * freed.
1349  |  *
1350  |  * Please note, it can return NULL in case of overlap
1351  |  * ranges, followed by WARN() report. Despite it is a
1883  | 			err |= (va->va_end > vend);
1884  |
1885  |  if (!WARN_ON_ONCE(err)) {
1886  | 				list_del_init(&va->list);
1887  |  WRITE_ONCE(vp->len, vp->len - 1);
1888  | 			} else {
1889  | 				va = NULL;
1890  | 			}
1891  | 		} else {
1892  | 			list_move_tail(&va->list, &vp->head);
1893  | 			va = NULL;
1894  | 		}
1895  | 	}
1896  | 	spin_unlock(&vn->pool_lock);
1897  |
1898  |  return va;
1899  | }
1900  |
1901  | static struct vmap_area *
1902  | node_alloc(unsigned long size, unsigned long align,
1903  |  unsigned long vstart, unsigned long vend,
1904  |  unsigned long *addr, unsigned int *vn_id)
1905  | {
1906  |  struct vmap_area *va;
1907  |
1908  | 	*vn_id = 0;
1909  | 	*addr = vend;
1910  |
1911  |  /*
1912  |  * Fallback to a global heap if not vmalloc or there
1913  |  * is only one node.
1914  |  */
1915  |  if (vstart != VMALLOC_START || vend != VMALLOC_END ||
1916  | 			nr_vmap_nodes == 1)
1917  |  return NULL;
1918  |
1919  | 	*vn_id = raw_smp_processor_id() % nr_vmap_nodes;
1920  | 	va = node_pool_del_va(id_to_node(*vn_id), size, align, vstart, vend);
1921  | 	*vn_id = encode_vn_id(*vn_id);
1922  |
1923  |  if (va)
1924  | 		*addr = va->va_start;
1925  |
1926  |  return va;
1927  | }
1928  |
1929  | /*
1930  |  * Allocate a region of KVA of the specified size and alignment, within the
1931  |  * vstart and vend.
1932  |  */
1933  | static struct vmap_area *alloc_vmap_area(unsigned long size,
1934  |  unsigned long align,
1935  |  unsigned long vstart, unsigned long vend,
1936  |  int node, gfp_t gfp_mask,
1937  |  unsigned long va_flags)
1938  | {
1939  |  struct vmap_node *vn;
1940  |  struct vmap_area *va;
1941  |  unsigned long freed;
1942  |  unsigned long addr;
1943  |  unsigned int vn_id;
1944  |  int purged = 0;
1945  |  int ret;
1946  |
1947  |  if (unlikely(!size || offset_in_page(size) || !is_power_of_2(align)))
1948  |  return ERR_PTR(-EINVAL);
1949  |
1950  |  if (unlikely(!vmap_initialized))
1951  |  return ERR_PTR(-EBUSY);
1952  |
1953  |  might_sleep();
1954  |
1955  |  /*
1956  |  * If a VA is obtained from a global heap(if it fails here)
1957  |  * it is anyway marked with this "vn_id" so it is returned
1958  |  * to this pool's node later. Such way gives a possibility
1959  |  * to populate pools based on users demand.
1960  |  *
1961  |  * On success a ready to go VA is returned.
1962  |  */
1963  | 	va = node_alloc(size, align, vstart, vend, &addr, &vn_id);
1964  |  if (!va) {
1965  | 		gfp_mask = gfp_mask & GFP_RECLAIM_MASK;
1966  |
1967  | 		va = kmem_cache_alloc_node(vmap_area_cachep, gfp_mask, node);
1968  |  if (unlikely(!va))
1969  |  return ERR_PTR(-ENOMEM);
1970  |
1971  |  /*
1972  |  * Only scan the relevant parts containing pointers to other objects
1973  |  * to avoid false negatives.
1974  |  */
1975  | 		kmemleak_scan_area(&va->rb_node, SIZE_MAX, gfp_mask);
1976  | 	}
1977  |
1978  | retry:
1979  |  if (addr == vend) {
1980  | 		preload_this_cpu_lock(&free_vmap_area_lock, gfp_mask, node);
1981  | 		addr = __alloc_vmap_area(&free_vmap_area_root, &free_vmap_area_list,
1982  | 			size, align, vstart, vend);
1983  | 		spin_unlock(&free_vmap_area_lock);
1984  | 	}
1985  |
1986  | 	trace_alloc_vmap_area(addr, size, align, vstart, vend, addr == vend);
1987  |
1988  |  /*
1989  |  * If an allocation fails, the "vend" address is
1990  |  * returned. Therefore trigger the overflow path.
1991  |  */
1992  |  if (unlikely(addr == vend))
1993  |  goto overflow;
1994  |
1995  | 	va->va_start = addr;
1996  | 	va->va_end = addr + size;
1997  | 	va->vm = NULL;
1998  | 	va->flags = (va_flags | vn_id);
1999  |
2000  | 	vn = addr_to_node(va->va_start);
2001  |
2002  | 	spin_lock(&vn->busy.lock);
2003  | 	insert_vmap_area(va, &vn->busy.root, &vn->busy.head);
2004  | 	spin_unlock(&vn->busy.lock);
2005  |
2006  |  BUG_ON(!IS_ALIGNED(va->va_start, align));
2007  |  BUG_ON(va->va_start < vstart);
2008  |  BUG_ON(va->va_end > vend);
2009  |
2010  | 	ret = kasan_populate_vmalloc(addr, size);
2011  |  if (ret) {
2012  | 		free_vmap_area(va);
2013  |  return ERR_PTR(ret);
2014  | 	}
2015  |
2016  |  return va;
2017  |
2018  | overflow:
2019  |  if (!purged) {
2020  | 		reclaim_and_purge_vmap_areas();
2021  | 		purged = 1;
2022  |  goto retry;
2023  | 	}
2024  |
2025  | 	freed = 0;
2026  | 	blocking_notifier_call_chain(&vmap_notify_list, 0, &freed);
2027  |
2028  |  if (freed > 0) {
2029  | 		purged = 0;
2030  |  goto retry;
2031  | 	}
2032  |
2033  |  if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit())
2034  |  pr_warn("vmap allocation for size %lu failed: use vmalloc=<size> to increase size\n",
2035  |  size);
2036  |
2037  | 	kmem_cache_free(vmap_area_cachep, va);
2038  |  return ERR_PTR(-EBUSY);
2039  | }
2040  |
2041  | int register_vmap_purge_notifier(struct notifier_block *nb)
2042  | {
2043  |  return blocking_notifier_chain_register(&vmap_notify_list, nb);
2044  | }
2045  | EXPORT_SYMBOL_GPL(register_vmap_purge_notifier);
2046  |
2911  |  * If you use this function for less than VMAP_MAX_ALLOC pages, it could be
2912  |  * faster than vmap so it's good.  But if you mix long-life and short-life
2913  |  * objects with vm_map_ram(), it could consume lots of address space through
2914  |  * fragmentation (especially on a 32bit machine).  You could see failures in
2915  |  * the end.  Please use this function for short-lived objects.
2916  |  *
2917  |  * Returns: a pointer to the address that has been mapped, or %NULL on failure
2918  |  */
2919  | void *vm_map_ram(struct page **pages, unsigned int count, int node)
2920  | {
2921  |  unsigned long size = (unsigned long)count << PAGE_SHIFT;
2922  |  unsigned long addr;
2923  |  void *mem;
2924  |
2925  |  if (likely(count <= VMAP_MAX_ALLOC)) {
2926  | 		mem = vb_alloc(size, GFP_KERNEL);
2927  |  if (IS_ERR(mem))
2928  |  return NULL;
2929  | 		addr = (unsigned long)mem;
2930  | 	} else {
2931  |  struct vmap_area *va;
2932  | 		va = alloc_vmap_area(size, PAGE_SIZE,
2933  |  VMALLOC_START, VMALLOC_END,
2934  | 				node, GFP_KERNEL, VMAP_RAM);
2935  |  if (IS_ERR(va))
2936  |  return NULL;
2937  |
2938  | 		addr = va->va_start;
2939  | 		mem = (void *)addr;
2940  | 	}
2941  |
2942  |  if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
2943  | 				pages, PAGE_SHIFT) < 0) {
2944  | 		vm_unmap_ram(mem, count);
2945  |  return NULL;
2946  | 	}
2947  |
2948  |  /*
2949  |  * Mark the pages as accessible, now that they are mapped.
2950  |  * With hardware tag-based KASAN, marking is skipped for
2951  |  * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
2952  |  */
2953  | 	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_PROT_NORMAL);
2954  |
2955  |  return mem;
2956  | }
2957  | EXPORT_SYMBOL(vm_map_ram);
2958  |
2959  | static struct vm_struct *vmlist __initdata;
2960  |
2961  | static inline unsigned int vm_area_page_order(struct vm_struct *vm)
2962  | {
2963  | #ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
2964  |  return vm->page_order;
2965  | #else
2966  |  return 0;
2967  | #endif
2968  | }
2969  |
2970  | static inline void set_vm_area_page_order(struct vm_struct *vm, unsigned int order)
2971  | {
2972  | #ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
2973  | 	vm->page_order = order;
2974  | #else
2975  |  BUG_ON(order != 0);
2976  | #endif
2977  | }
2978  |
2979  | /**
2980  |  * vm_area_add_early - add vmap area early during boot
2981  |  * @vm: vm_struct to add
2982  |  *
2983  |  * This function is used to add fixed kernel vm area to vmlist before
2984  |  * vmalloc_init() is called.  @vm->addr, @vm->size, and @vm->flags
2985  |  * should contain proper values and the other fields should be zero.
2986  |  *
2987  |  * DO NOT USE THIS FUNCTION UNLESS YOU KNOW WHAT YOU'RE DOING.
2988  |  */
2989  | void __init vm_area_add_early(struct vm_struct *vm)
2990  | {
2991  |  struct vm_struct *tmp, **p;
2992  |
2993  |  BUG_ON(vmap_initialized);
2994  |  for (p = &vmlist; (tmp = *p) != NULL; p = &tmp->next) {
2995  |  if (tmp->addr >= vm->addr) {
2996  |  BUG_ON(tmp->addr < vm->addr + vm->size);
2997  |  break;
2998  | 		} else
2999  |  BUG_ON(tmp->addr + tmp->size > vm->addr);
3000  | 	}
3001  | 	vm->next = *p;
3002  | 	*p = vm;
3003  | }
3004  |
3005  | /**
3006  |  * vm_area_register_early - register vmap area early during boot
3007  |  * @vm: vm_struct to register
3008  |  * @align: requested alignment
3009  |  *
3010  |  * This function is used to register kernel vm area before
3011  |  * vmalloc_init() is called.  @vm->size and @vm->flags should contain
3012  |  * proper values on entry and other fields should be zero.  On return,
3013  |  * vm->addr contains the allocated address.
3014  |  *
3015  |  * DO NOT USE THIS FUNCTION UNLESS YOU KNOW WHAT YOU'RE DOING.
3016  |  */
3017  | void __init vm_area_register_early(struct vm_struct *vm, size_t align)
3018  | {
3019  |  unsigned long addr = ALIGN(VMALLOC_START, align);
3020  |  struct vm_struct *cur, **p;
3021  |
3022  |  BUG_ON(vmap_initialized);
3023  |
3024  |  for (p = &vmlist; (cur = *p) != NULL; p = &cur->next) {
3025  |  if ((unsigned long)cur->addr - addr >= vm->size)
3026  |  break;
3027  | 		addr = ALIGN((unsigned long)cur->addr + cur->size, align);
3028  | 	}
3029  |
3030  |  BUG_ON(addr > VMALLOC_END - vm->size);
3031  | 	vm->addr = (void *)addr;
3032  | 	vm->next = *p;
3033  | 	*p = vm;
3034  | 	kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
3035  | }
3036  |
3037  | static inline void setup_vmalloc_vm_locked(struct vm_struct *vm,
3038  |  struct vmap_area *va, unsigned long flags, const void *caller)
3039  | {
3040  | 	vm->flags = flags;
3041  | 	vm->addr = (void *)va->va_start;
3042  | 	vm->size = va->va_end - va->va_start;
3043  | 	vm->caller = caller;
3044  | 	va->vm = vm;
3045  | }
3046  |
3047  | static void setup_vmalloc_vm(struct vm_struct *vm, struct vmap_area *va,
3048  |  unsigned long flags, const void *caller)
3049  | {
3050  |  struct vmap_node *vn = addr_to_node(va->va_start);
3051  |
3052  | 	spin_lock(&vn->busy.lock);
3053  | 	setup_vmalloc_vm_locked(vm, va, flags, caller);
3054  | 	spin_unlock(&vn->busy.lock);
3055  | }
3056  |
3057  | static void clear_vm_uninitialized_flag(struct vm_struct *vm)
3058  | {
3059  |  /*
3060  |  * Before removing VM_UNINITIALIZED,
3061  |  * we should make sure that vm has proper values.
3062  |  * Pair with smp_rmb() in show_numa_info().
3063  |  */
3064  |  smp_wmb();
3065  | 	vm->flags &= ~VM_UNINITIALIZED;
3066  | }
3067  |
3068  | static struct vm_struct *__get_vm_area_node(unsigned long size,
3069  |  unsigned long align, unsigned long shift, unsigned long flags,
3070  |  unsigned long start, unsigned long end, int node,
3071  | 		gfp_t gfp_mask, const void *caller)
3072  | {
3073  |  struct vmap_area *va;
3074  |  struct vm_struct *area;
3075  |  unsigned long requested_size = size;
3076  |
3077  |  BUG_ON(in_interrupt());
3078  | 	size = ALIGN(size, 1ul << shift);
3079  |  if (unlikely(!size))
3080  |  return NULL;
3081  |
3082  |  if (flags & VM_IOREMAP)
3083  | 		align = 1ul << clamp_t(int, get_count_order_long(size),
3084  |  PAGE_SHIFT, IOREMAP_MAX_ORDER);
3085  |
3086  | 	area = kzalloc_node(sizeof(*area), gfp_mask & GFP_RECLAIM_MASK, node);
3087  |  if (unlikely(!area))
3088  |  return NULL;
3089  |
3090  |  if (!(flags & VM_NO_GUARD))
3091  | 		size += PAGE_SIZE;
3092  |
3093  | 	va = alloc_vmap_area(size, align, start, end, node, gfp_mask, 0);
3094  |  if (IS_ERR(va)) {
3095  | 		kfree(area);
3096  |  return NULL;
3097  | 	}
3098  |
3099  | 	setup_vmalloc_vm(area, va, flags, caller);
3100  |
3101  |  /*
3102  |  * Mark pages for non-VM_ALLOC mappings as accessible. Do it now as a
3103  |  * best-effort approach, as they can be mapped outside of vmalloc code.
3104  |  * For VM_ALLOC mappings, the pages are marked as accessible after
3105  |  * getting mapped in __vmalloc_node_range().
3106  |  * With hardware tag-based KASAN, marking is skipped for
3107  |  * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
3108  |  */
3109  |  if (!(flags & VM_ALLOC))
3110  | 		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size,
3111  |  KASAN_VMALLOC_PROT_NORMAL);
3112  |
3113  |  return area;
3114  | }
3115  |
3116  | struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
3117  |  unsigned long start, unsigned long end,
3118  |  const void *caller)
3119  | {
3120  |  return __get_vm_area_node(size, 1, PAGE_SHIFT, flags, start, end,
3121  |  NUMA_NO_NODE, GFP_KERNEL, caller);
3122  | }
3123  |
3124  | /**
3125  |  * get_vm_area - reserve a contiguous kernel virtual area
3126  |  * @size:	 size of the area
3127  |  * @flags:	 %VM_IOREMAP for I/O mappings or VM_ALLOC
3128  |  *
3129  |  * Search an area of @size in the kernel virtual mapping area,
3130  |  * and reserved it for out purposes.  Returns the area descriptor
3131  |  * on success or %NULL on failure.
3132  |  *
3133  |  * Return: the area descriptor on success or %NULL on failure.
3134  |  */
3135  | struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
3136  | {
3137  |  return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
3138  |  VMALLOC_START, VMALLOC_END,
3139  |  NUMA_NO_NODE, GFP_KERNEL,
3140  | 				  __builtin_return_address(0));
3141  | }
3142  |
3143  | struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags,
3549  |  * and compaction etc.
3550  |  */
3551  | 		alloc_gfp &= ~__GFP_NOFAIL;
3552  | 		nofail = true;
3553  | 	}
3554  |
3555  |  /* High-order pages or fallback path if "bulk" fails. */
3556  |  while (nr_allocated < nr_pages) {
3557  |  if (fatal_signal_pending(current))
3558  |  break;
3559  |
3560  |  if (nid == NUMA_NO_NODE)
3561  | 			page = alloc_pages(alloc_gfp, order);
3562  |  else
3563  | 			page = alloc_pages_node(nid, alloc_gfp, order);
3564  |  if (unlikely(!page)) {
3565  |  if (!nofail)
3566  |  break;
3567  |
3568  |  /* fall back to the zero order allocations */
3569  | 			alloc_gfp |= __GFP_NOFAIL;
3570  | 			order = 0;
3571  |  continue;
3572  | 		}
3573  |
3574  |  /*
3575  |  * Higher order allocations must be able to be treated as
3576  |  * indepdenent small pages by callers (as they can with
3577  |  * small-page vmallocs). Some drivers do their own refcounting
3578  |  * on vmalloc_to_page() pages, some use page->mapping,
3579  |  * page->lru, etc.
3580  |  */
3581  |  if (order)
3582  | 			split_page(page, order);
3583  |
3584  |  /*
3585  |  * Careful, we allocate and map page-order pages, but
3586  |  * tracking is done per PAGE_SIZE page so as to keep the
3587  |  * vm_struct APIs independent of the physical/mapped size.
3588  |  */
3589  |  for (i = 0; i < (1U << order); i++)
3590  | 			pages[nr_allocated + i] = page + i;
3591  |
3592  |  cond_resched();
3593  | 		nr_allocated += 1U << order;
3594  | 	}
3595  |
3596  |  return nr_allocated;
3597  | }
3598  |
3599  | static void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
3600  | 				 pgprot_t prot, unsigned int page_shift,
3601  |  int node)
3602  | {
3603  |  const gfp_t nested_gfp = (gfp_mask & GFP_RECLAIM_MASK) | __GFP_ZERO;
3604  | 	bool nofail = gfp_mask & __GFP_NOFAIL;
3605  |  unsigned long addr = (unsigned long)area->addr;
3606  |  unsigned long size = get_vm_area_size(area);
3607  |  unsigned long array_size;
3608  |  unsigned int nr_small_pages = size >> PAGE_SHIFT;
3609  |  unsigned int page_order;
3610  |  unsigned int flags;
3611  |  int ret;
3612  |
3613  | 	array_size = (unsigned long)nr_small_pages * sizeof(struct page *);
3614  |
3615  |  if (!(gfp_mask & (GFP_DMA | GFP_DMA32)))
    15←Assuming the condition is false→
    16←Taking false branch→
3616  | 		gfp_mask |= __GFP_HIGHMEM;
3617  |
3618  |  /* Please note that the recursion is strictly bounded. */
3619  |  if (array_size > PAGE_SIZE) {
    17←Assuming the condition is true→
    18←Taking true branch→
3620  |  area->pages = __vmalloc_node(array_size, 1, nested_gfp, node,
3621  | 					area->caller);
3622  | 	} else {
3623  | 		area->pages = kmalloc_node(array_size, nested_gfp, node);
3624  | 	}
3625  |
3626  |  if (!area->pages) {
    19←Assuming field 'pages' is non-null→
    20←Taking false branch→
3627  | 		warn_alloc(gfp_mask, NULL,
3628  |  "vmalloc error: size %lu, failed to allocated page array size %lu",
3629  | 			nr_small_pages * PAGE_SIZE, array_size);
3630  | 		free_vm_area(area);
3631  |  return NULL;
3632  | 	}
3633  |
3634  |  set_vm_area_page_order(area, page_shift - PAGE_SHIFT);
3635  | 	page_order = vm_area_page_order(area);
3636  |
3637  | 	area->nr_pages = vm_area_alloc_pages(gfp_mask | __GFP_NOWARN,
3638  | 		node, page_order, nr_small_pages, area->pages);
3639  |
3640  | 	atomic_long_add(area->nr_pages, &nr_vmalloc_pages);
3641  |  if (gfp_mask & __GFP_ACCOUNT) {
    21←Assuming the condition is true→
    22←Taking true branch→
3642  |  int i;
3643  |
3644  |  for (i = 0; i < area->nr_pages; i++)
    23←Assuming 'i' is >= field 'nr_pages'→
    24←Loop condition is false. Execution continues on line 3652→
3645  | 			mod_memcg_page_state(area->pages[i], MEMCG_VMALLOC, 1);
3646  | 	}
3647  |
3648  |  /*
3649  |  * If not enough pages were obtained to accomplish an
3650  |  * allocation request, free them via vfree() if any.
3651  |  */
3652  |  if (area->nr_pages != nr_small_pages) {
    25←Assuming 'nr_small_pages' is not equal to field 'nr_pages'→
3653  |  /*
3654  |  * vm_area_alloc_pages() can fail due to insufficient memory but
3655  |  * also:-
3656  |  *
3657  |  * - a pending fatal signal
3658  |  * - insufficient huge page-order pages
3659  |  *
3660  |  * Since we always retry allocations at order-0 in the huge page
3661  |  * case a warning for either is spurious.
3662  |  */
3663  |  if (!fatal_signal_pending(current) && page_order25.1'page_order' is equal to 0 == 0)
    26←Taking true branch→
3664  |  warn_alloc(gfp_mask, NULL,
3665  |  "vmalloc error: size %lu, failed to allocate pages",
3666  | 				area->nr_pages * PAGE_SIZE);
3667  |  goto fail;
    27←Control jumps to line 3701→
3668  | 	}
3669  |
3670  |  /*
3671  |  * page tables allocations ignore external gfp mask, enforce it
3672  |  * by the scope API
3673  |  */
3674  |  if ((gfp_mask & (__GFP_FS | __GFP_IO)) == __GFP_IO)
3675  | 		flags = memalloc_nofs_save();
3676  |  else if ((gfp_mask & (__GFP_FS | __GFP_IO)) == 0)
3677  | 		flags = memalloc_noio_save();
3678  |
3679  |  do {
3680  | 		ret = vmap_pages_range(addr, addr + size, prot, area->pages,
3681  | 			page_shift);
3682  |  if (nofail && (ret < 0))
3683  | 			schedule_timeout_uninterruptible(1);
3684  | 	} while (nofail && (ret < 0));
3685  |
3686  |  if ((gfp_mask & (__GFP_FS | __GFP_IO)) == __GFP_IO)
3687  | 		memalloc_nofs_restore(flags);
3688  |  else if ((gfp_mask & (__GFP_FS | __GFP_IO)) == 0)
3689  | 		memalloc_noio_restore(flags);
3690  |
3691  |  if (ret < 0) {
3692  | 		warn_alloc(gfp_mask, NULL,
3693  |  "vmalloc error: size %lu, failed to map pages",
3694  | 			area->nr_pages * PAGE_SIZE);
3695  |  goto fail;
3696  | 	}
3697  |
3698  |  return area->addr;
3699  |
3700  | fail:
3701  |  vfree(area->addr);
    28←Freeing unowned field in shared error label; possible double free
3702  |  return NULL;
3703  | }
3704  |
3705  | /**
3706  |  * __vmalloc_node_range - allocate virtually contiguous memory
3707  |  * @size:		  allocation size
3708  |  * @align:		  desired alignment
3709  |  * @start:		  vm area range start
3710  |  * @end:		  vm area range end
3711  |  * @gfp_mask:		  flags for the page level allocator
3712  |  * @prot:		  protection mask for the allocated pages
3713  |  * @vm_flags:		  additional vm area flags (e.g. %VM_NO_GUARD)
3714  |  * @node:		  node to use for allocation or NUMA_NO_NODE
3715  |  * @caller:		  caller's return address
3716  |  *
3717  |  * Allocate enough pages to cover @size from the page level
3718  |  * allocator with @gfp_mask flags. Please note that the full set of gfp
3719  |  * flags are not supported. GFP_KERNEL, GFP_NOFS and GFP_NOIO are all
3720  |  * supported.
3721  |  * Zone modifiers are not supported. From the reclaim modifiers
3722  |  * __GFP_DIRECT_RECLAIM is required (aka GFP_NOWAIT is not supported)
3723  |  * and only __GFP_NOFAIL is supported (i.e. __GFP_NORETRY and
3724  |  * __GFP_RETRY_MAYFAIL are not supported).
3725  |  *
3726  |  * __GFP_NOWARN can be used to suppress failures messages.
3727  |  *
3728  |  * Map them into contiguous kernel virtual space, using a pagetable
3729  |  * protection of @prot.
3730  |  *
3731  |  * Return: the address of the area or %NULL on failure
3732  |  */
3733  | void *__vmalloc_node_range(unsigned long size, unsigned long align,
3734  |  unsigned long start, unsigned long end, gfp_t gfp_mask,
3735  | 			pgprot_t prot, unsigned long vm_flags, int node,
3736  |  const void *caller)
3737  | {
3738  |  struct vm_struct *area;
3739  |  void *ret;
3740  | 	kasan_vmalloc_flags_t kasan_flags = KASAN_VMALLOC_NONE;
3741  |  unsigned long real_size = size;
3742  |  unsigned long real_align = align;
3743  |  unsigned int shift = PAGE_SHIFT;
3744  |
3745  |  if (WARN_ON_ONCE(!size))
    1Assuming 'size' is not equal to 0→
    2←Taking false branch→
    3←Taking false branch→
3746  |  return NULL;
3747  |
3748  |  if ((size >> PAGE_SHIFT) > totalram_pages()) {
    4←Assuming the condition is false→
3749  | 		warn_alloc(gfp_mask, NULL,
3750  |  "vmalloc error: size %lu, exceeds total pages",
3751  | 			real_size);
3752  |  return NULL;
3753  | 	}
3754  |
3755  |  if (vmap_allow_huge && (vm_flags & VM_ALLOW_HUGE_VMAP)) {
    5←Assuming 'vmap_allow_huge' is false→
3756  |  unsigned long size_per_node;
3757  |
3758  |  /*
3759  |  * Try huge pages. Only try for PAGE_KERNEL allocations,
3760  |  * others like modules don't yet expect huge pages in
3761  |  * their allocations due to apply_to_page_range not
3762  |  * supporting them.
3763  |  */
3764  |
3765  | 		size_per_node = size;
3766  |  if (node == NUMA_NO_NODE)
3767  | 			size_per_node /= num_online_nodes();
3768  |  if (arch_vmap_pmd_supported(prot) && size_per_node >= PMD_SIZE)
3769  | 			shift = PMD_SHIFT;
3770  |  else
3771  | 			shift = arch_vmap_pte_supported_shift(size_per_node);
3772  |
3773  | 		align = max(real_align, 1UL << shift);
3774  | 		size = ALIGN(real_size, 1UL << shift);
3775  | 	}
3776  |
3777  | again:
3778  |  area = __get_vm_area_node(real_size, align, shift, VM_ALLOC |
3779  |  VM_UNINITIALIZED | vm_flags, start, end, node,
3780  | 				  gfp_mask, caller);
3781  |  if (!area5.1'area' is null10.1'area' is non-null) {
    6←Taking true branch→
    11←Taking false branch→
3782  |  bool nofail = gfp_mask & __GFP_NOFAIL;
3783  |  warn_alloc(gfp_mask, NULL,
3784  |  "vmalloc error: size %lu, vm_struct allocation failed%s",
3785  | 			real_size, (nofail) ? ". Retrying." : "");
    7←Assuming 'nofail' is true→
    8←'?' condition is true→
3786  |  if (nofail8.1'nofail' is true) {
    9←Taking true branch→
3787  |  schedule_timeout_uninterruptible(1);
3788  |  goto again;
    10←Control jumps to line 3778→
3789  | 		}
3790  |  goto fail;
3791  | 	}
3792  |
3793  |  /*
3794  |  * Prepare arguments for __vmalloc_area_node() and
3795  |  * kasan_unpoison_vmalloc().
3796  |  */
3797  |  if (pgprot_val(prot) == pgprot_val(PAGE_KERNEL)) {
    12←Assuming '' is not equal to ''→
    13←Taking false branch→
3798  |  if (kasan_hw_tags_enabled()) {
3799  |  /*
3800  |  * Modify protection bits to allow tagging.
3801  |  * This must be done before mapping.
3802  |  */
3803  | 			prot = arch_vmap_pgprot_tagged(prot);
3804  |
3805  |  /*
3806  |  * Skip page_alloc poisoning and zeroing for physical
3807  |  * pages backing VM_ALLOC mapping. Memory is instead
3808  |  * poisoned and zeroed by kasan_unpoison_vmalloc().
3809  |  */
3810  | 			gfp_mask |= __GFP_SKIP_KASAN | __GFP_SKIP_ZERO;
3811  | 		}
3812  |
3813  |  /* Take note that the mapping is PAGE_KERNEL. */
3814  | 		kasan_flags |= KASAN_VMALLOC_PROT_NORMAL;
3815  | 	}
3816  |
3817  |  /* Allocate physical pages and map them into vmalloc space. */
3818  |  ret = __vmalloc_area_node(area, gfp_mask, prot, shift, node);
    14←Calling '__vmalloc_area_node'→
3819  |  if (!ret)
3820  |  goto fail;
3821  |
3822  |  /*
3823  |  * Mark the pages as accessible, now that they are mapped.
3824  |  * The condition for setting KASAN_VMALLOC_INIT should complement the
3825  |  * one in post_alloc_hook() with regards to the __GFP_SKIP_ZERO check
3826  |  * to make sure that memory is initialized under the same conditions.
3827  |  * Tag-based KASAN modes only assign tags to normal non-executable
3828  |  * allocations, see __kasan_unpoison_vmalloc().
3829  |  */
3830  | 	kasan_flags |= KASAN_VMALLOC_VM_ALLOC;
3831  |  if (!want_init_on_free() && want_init_on_alloc(gfp_mask) &&
3832  | 	    (gfp_mask & __GFP_SKIP_ZERO))
3833  | 		kasan_flags |= KASAN_VMALLOC_INIT;
3834  |  /* KASAN_VMALLOC_PROT_NORMAL already set if required. */
3835  | 	area->addr = kasan_unpoison_vmalloc(area->addr, real_size, kasan_flags);
3836  |
3837  |  /*
3838  |  * In this function, newly allocated vm_struct has VM_UNINITIALIZED
3839  |  * flag. It means that vm_struct is not fully initialized.
3840  |  * Now, it is fully initialized, so remove this flag here.
3841  |  */
3842  | 	clear_vm_uninitialized_flag(area);
3843  |
3844  | 	size = PAGE_ALIGN(size);
3845  |  if (!(vm_flags & VM_DEFER_KMEMLEAK))
3846  | 		kmemleak_vmalloc(area, size, gfp_mask);
3847  |
3848  |  return area->addr;

Analysis:
- Decision: NotABug
- Reason: The reported site is in __vmalloc_area_node()’s fail label calling vfree(area->addr). This does not match the target bug pattern. In this function:
  - area->addr is set by __get_vm_area_node() before entering __vmalloc_area_node(), and the vm_struct is registered (with VM_UNINITIALIZED) so that vfree() can clean it up on failure paths.
  - There are two distinct failure cleanups:
    - If allocating the pages array (area->pages) fails, the function uses free_vm_area(area) and returns immediately (no jump to the shared fail label).
    - If page allocation is partial or mapping fails (the two goto fail sites), nothing has freed the vm area yet. In those cases, vfree(area->addr) is the correct single cleanup that will free the vm_struct, the vmap area, and any partially allocated/mapped pages.
  - Thus, there is no path where the same resource is freed twice via a shared error label. The earlier cleanup path returns directly and does not fall through to the fail label.
  - This differs from the target bug pattern (freeing a callee-managed/conditionally allocated pointer unconditionally in a shared label). Here, the resource is owned and consistently freed, and the shared label is only used by paths that have not freed it yet.

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

    // New: Variables assigned from allocator-like calls: VarDecl -> locations.
    llvm::DenseMap<const VarDecl*, llvm::SmallVector<SourceLocation, 4>> VarAllocLocs;

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
      const SourceLocation CurLoc = BO->getBeginLoc();
      const SourceManager &SM = C.getSourceManager();

      // Track fields assigned from call expressions (potential allocators),
      // and record the earliest location.
      if (const auto *ME = dyn_cast<MemberExpr>(LHS)) {
        const ValueDecl *VD = ME->getMemberDecl();
        if (const auto *FD = dyn_cast_or_null<FieldDecl>(VD)) {
          const ParmVarDecl *BaseP = getDirectBaseParam(ME->getBase());
          if (BaseP) {
            // NULL set tracking.
            if (isExplicitNullExpr(RHS)) {
              NullSetLocs[FD->getCanonicalDecl()][BaseP].push_back(CurLoc);
            }
            // Allocator-assignment tracking when RHS is a call.
            if (const auto *RCE = dyn_cast<CallExpr>(RHS)) {
              if (callExprLooksLikeAllocator(RCE, C)) {
                AllocAssignLocs[FD->getCanonicalDecl()][BaseP].push_back(CurLoc);
              }
            }
            // New: Allocator-assignment tracking when RHS is a variable previously
            //       assigned from an allocator in this function.
            if (const auto *RDRE = dyn_cast<DeclRefExpr>(RHS)) {
              if (const auto *RVD = dyn_cast<VarDecl>(RDRE->getDecl())) {
                auto It = VarAllocLocs.find(RVD->getCanonicalDecl());
                if (It != VarAllocLocs.end()) {
                  const auto &ALocs = It->second;
                  bool HasPriorAlloc = false;
                  for (SourceLocation LA : ALocs) {
                    if (SM.isBeforeInTranslationUnit(LA, CurLoc)) {
                      HasPriorAlloc = true;
                      break;
                    }
                  }
                  if (HasPriorAlloc) {
                    AllocAssignLocs[FD->getCanonicalDecl()][BaseP].push_back(CurLoc);
                  }
                }
              }
            }
          }
        }
      }

      // Track variables assigned from allocator calls: var = kmalloc(...);
      if (const auto *LDRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (const auto *LVD = dyn_cast<VarDecl>(LDRE->getDecl())) {
          if (const auto *RCE = dyn_cast<CallExpr>(RHS)) {
            if (callExprLooksLikeAllocator(RCE, C)) {
              VarAllocLocs[LVD->getCanonicalDecl()].push_back(CurLoc);
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
        auto It = FirstSetLoc.find(CanonFD);
        if (It == FirstSetLoc.end()) {
          FirstSetLoc[CanonFD] = CurLoc;
        } else {
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
