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

File:| /scratch/chenyuan-data/linux-debug/net/core/neighbour.c
---|---
Warning:| line 533, column 2
Shift done in 32-bit, widened after; cast left operand to 64-bit before <<

### Annotated Source Code


62    | #endif
63    |
64    | /*
65    |  Neighbour hash table buckets are protected with rwlock tbl->lock.
66    |
67    |  - All the scans/updates to hash buckets MUST be made under this lock.
68    |  - NOTHING clever should be made under this lock: no callbacks
69    |  to protocol backends, no attempts to send something to network.
70    |  It will result in deadlocks, if backend/driver wants to use neighbour
71    |  cache.
72    |  - If the entry requires some non-trivial actions, increase
73    |  its reference count and release table lock.
74    |
75    |  Neighbour entries are protected:
76    |  - with reference count.
77    |  - with rwlock neigh->lock
78    |
79    |  Reference count prevents destruction.
80    |
81    |  neigh->lock mainly serializes ll address data and its validity state.
82    |  However, the same lock is used to protect another entry fields:
83    |  - timer
84    |  - resolution queue
85    |
86    |  Again, nothing clever shall be made under neigh->lock,
87    |  the most complicated procedure, which we allow is dev->hard_header.
88    |  It is supposed, that dev->hard_header is simplistic and does
89    |  not make callbacks to neighbour tables.
90    |  */
91    |
92    | static int neigh_blackhole(struct neighbour *neigh, struct sk_buff *skb)
93    | {
94    | 	kfree_skb(skb);
95    |  return -ENETDOWN;
96    | }
97    |
98    | static void neigh_cleanup_and_release(struct neighbour *neigh)
99    | {
100   | 	trace_neigh_cleanup_and_release(neigh, 0);
101   | 	__neigh_notify(neigh, RTM_DELNEIGH, 0, 0);
102   | 	call_netevent_notifiers(NETEVENT_NEIGH_UPDATE, neigh);
103   | 	neigh_release(neigh);
104   | }
105   |
106   | /*
107   |  * It is random distribution in the interval (1/2)*base...(3/2)*base.
108   |  * It corresponds to default IPv6 settings and is not overridable,
109   |  * because it is really reasonable choice.
110   |  */
111   |
112   | unsigned long neigh_rand_reach_time(unsigned long base)
113   | {
114   |  return base ? get_random_u32_below(base) + (base >> 1) : 0;
115   | }
116   | EXPORT_SYMBOL(neigh_rand_reach_time);
117   |
118   | static void neigh_mark_dead(struct neighbour *n)
119   | {
120   | 	n->dead = 1;
121   |  if (!list_empty(&n->gc_list)) {
122   | 		list_del_init(&n->gc_list);
123   | 		atomic_dec(&n->tbl->gc_entries);
124   | 	}
125   |  if (!list_empty(&n->managed_list))
126   | 		list_del_init(&n->managed_list);
127   | }
128   |
129   | static void neigh_update_gc_list(struct neighbour *n)
130   | {
131   | 	bool on_gc_list, exempt_from_gc;
132   |
133   |  write_lock_bh(&n->tbl->lock);
134   |  write_lock(&n->lock);
135   |  if (n->dead)
136   |  goto out;
137   |
138   |  /* remove from the gc list if new state is permanent or if neighbor
139   |  * is externally learned; otherwise entry should be on the gc list
140   |  */
141   | 	exempt_from_gc = n->nud_state & NUD_PERMANENT ||
142   | 			 n->flags & NTF_EXT_LEARNED;
143   | 	on_gc_list = !list_empty(&n->gc_list);
144   |
481   | 	gc_thresh3 = READ_ONCE(tbl->gc_thresh3);
482   |  if (entries >= gc_thresh3 ||
483   | 	    (entries >= READ_ONCE(tbl->gc_thresh2) &&
484   |  time_after(now, READ_ONCE(tbl->last_flush) + 5 * HZ))) {
485   |  if (!neigh_forced_gc(tbl) && entries >= gc_thresh3) {
486   |  net_info_ratelimited("%s: neighbor table overflow!\n",
487   |  tbl->id);
488   |  NEIGH_CACHE_STAT_INC(tbl, table_fulls);
489   |  goto out_entries;
490   | 		}
491   | 	}
492   |
493   | do_alloc:
494   | 	n = kzalloc(tbl->entry_size + dev->neigh_priv_len, GFP_ATOMIC);
495   |  if (!n)
496   |  goto out_entries;
497   |
498   | 	__skb_queue_head_init(&n->arp_queue);
499   |  rwlock_init(&n->lock);
500   |  seqlock_init(&n->ha_lock);
501   | 	n->updated	  = n->used = now;
502   | 	n->nud_state	  = NUD_NONE;
503   | 	n->output	  = neigh_blackhole;
504   | 	n->flags	  = flags;
505   |  seqlock_init(&n->hh.hh_lock);
506   | 	n->parms	  = neigh_parms_clone(&tbl->parms);
507   |  timer_setup(&n->timer, neigh_timer_handler, 0);
508   |
509   |  NEIGH_CACHE_STAT_INC(tbl, allocs);
510   | 	n->tbl		  = tbl;
511   | 	refcount_set(&n->refcnt, 1);
512   | 	n->dead		  = 1;
513   | 	INIT_LIST_HEAD(&n->gc_list);
514   | 	INIT_LIST_HEAD(&n->managed_list);
515   |
516   | 	atomic_inc(&tbl->entries);
517   | out:
518   |  return n;
519   |
520   | out_entries:
521   |  if (!exempt_from_gc)
522   | 		atomic_dec(&tbl->gc_entries);
523   |  goto out;
524   | }
525   |
526   | static void neigh_get_hash_rnd(u32 *x)
527   | {
528   | 	*x = get_random_u32() | 1;
529   | }
530   |
531   | static struct neigh_hash_table *neigh_hash_alloc(unsigned int shift)
532   | {
533   |  size_t size = (1 << shift) * sizeof(struct neighbour *);
    8←Shift done in 32-bit, widened after; cast left operand to 64-bit before <<
534   |  struct neigh_hash_table *ret;
535   |  struct neighbour __rcu **buckets;
536   |  int i;
537   |
538   | 	ret = kmalloc(sizeof(*ret), GFP_ATOMIC);
539   |  if (!ret)
540   |  return NULL;
541   |  if (size <= PAGE_SIZE) {
542   | 		buckets = kzalloc(size, GFP_ATOMIC);
543   | 	} else {
544   | 		buckets = (struct neighbour __rcu **)
545   | 			  __get_free_pages(GFP_ATOMIC | __GFP_ZERO,
546   | 					   get_order(size));
547   | 		kmemleak_alloc(buckets, size, 1, GFP_ATOMIC);
548   | 	}
549   |  if (!buckets) {
550   | 		kfree(ret);
551   |  return NULL;
552   | 	}
553   | 	ret->hash_buckets = buckets;
554   | 	ret->hash_shift = shift;
555   |  for (i = 0; i < NEIGH_NUM_HASH_RND; i++)
556   | 		neigh_get_hash_rnd(&ret->hash_rnd[i]);
557   |  return ret;
558   | }
559   |
560   | static void neigh_hash_free_rcu(struct rcu_head *head)
561   | {
562   |  struct neigh_hash_table *nht = container_of(head,
563   |  struct neigh_hash_table,
1724  | 		p->dev = dev;
1725  | 		write_pnet(&p->net, net);
1726  | 		p->sysctl_table = NULL;
1727  |
1728  |  if (ops->ndo_neigh_setup && ops->ndo_neigh_setup(dev, p)) {
1729  | 			netdev_put(dev, &p->dev_tracker);
1730  | 			kfree(p);
1731  |  return NULL;
1732  | 		}
1733  |
1734  |  write_lock_bh(&tbl->lock);
1735  | 		list_add(&p->list, &tbl->parms.list);
1736  |  write_unlock_bh(&tbl->lock);
1737  |
1738  | 		neigh_parms_data_state_cleanall(p);
1739  | 	}
1740  |  return p;
1741  | }
1742  | EXPORT_SYMBOL(neigh_parms_alloc);
1743  |
1744  | static void neigh_rcu_free_parms(struct rcu_head *head)
1745  | {
1746  |  struct neigh_parms *parms =
1747  |  container_of(head, struct neigh_parms, rcu_head);
1748  |
1749  | 	neigh_parms_put(parms);
1750  | }
1751  |
1752  | void neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms)
1753  | {
1754  |  if (!parms || parms == &tbl->parms)
1755  |  return;
1756  |  write_lock_bh(&tbl->lock);
1757  | 	list_del(&parms->list);
1758  | 	parms->dead = 1;
1759  |  write_unlock_bh(&tbl->lock);
1760  | 	netdev_put(parms->dev, &parms->dev_tracker);
1761  | 	call_rcu(&parms->rcu_head, neigh_rcu_free_parms);
1762  | }
1763  | EXPORT_SYMBOL(neigh_parms_release);
1764  |
1765  | static void neigh_parms_destroy(struct neigh_parms *parms)
1766  | {
1767  | 	kfree(parms);
1768  | }
1769  |
1770  | static struct lock_class_key neigh_table_proxy_queue_class;
1771  |
1772  | static struct neigh_table *neigh_tables[NEIGH_NR_TABLES] __read_mostly;
1773  |
1774  | void neigh_table_init(int index, struct neigh_table *tbl)
1775  | {
1776  |  unsigned long now = jiffies;
1777  |  unsigned long phsize;
1778  |
1779  | 	INIT_LIST_HEAD(&tbl->parms_list);
1780  | 	INIT_LIST_HEAD(&tbl->gc_list);
1781  | 	INIT_LIST_HEAD(&tbl->managed_list);
1782  |
1783  | 	list_add(&tbl->parms.list, &tbl->parms_list);
1784  | 	write_pnet(&tbl->parms.net, &init_net);
1785  | 	refcount_set(&tbl->parms.refcnt, 1);
1786  | 	tbl->parms.reachable_time =
1787  | 			  neigh_rand_reach_time(NEIGH_VAR(&tbl->parms, BASE_REACHABLE_TIME));
1788  | 	tbl->parms.qlen = 0;
1789  |
1790  | 	tbl->stats = alloc_percpu(struct neigh_statistics);
1791  |  if (!tbl->stats)
    1Assuming field 'stats' is non-null→
    2←Taking false branch→
1792  | 		panic("cannot create neighbour cache statistics");
1793  |
1794  | #ifdef CONFIG_PROC_FS
1795  |  if (!proc_create_seq_data(tbl->id, 0, init_net.proc_net_stat,
    3←Assuming the condition is false→
1796  |  &neigh_stat_seq_ops, tbl))
1797  | 		panic("cannot create neighbour proc dir entry");
1798  | #endif
1799  |
1800  |  RCU_INIT_POINTER(tbl->nht, neigh_hash_alloc(3));
    4←Taking false branch→
    5←Taking false branch→
    6←Loop condition is false.  Exiting loop→
    7←Calling 'neigh_hash_alloc'→
1801  |
1802  | 	phsize = (PNEIGH_HASHMASK + 1) * sizeof(struct pneigh_entry *);
1803  | 	tbl->phash_buckets = kzalloc(phsize, GFP_KERNEL);
1804  |
1805  |  if (!tbl->nht || !tbl->phash_buckets)
1806  | 		panic("cannot allocate neighbour cache hashes");
1807  |
1808  |  if (!tbl->entry_size)
1809  | 		tbl->entry_size = ALIGN(offsetof(struct neighbour, primary_key) +
1810  |  tbl->key_len, NEIGH_PRIV_ALIGN);
1811  |  else
1812  |  WARN_ON(tbl->entry_size % NEIGH_PRIV_ALIGN);
1813  |
1814  |  rwlock_init(&tbl->lock);
1815  |
1816  |  INIT_DEFERRABLE_WORK(&tbl->gc_work, neigh_periodic_work);
1817  | 	queue_delayed_work(system_power_efficient_wq, &tbl->gc_work,
1818  | 			tbl->parms.reachable_time);
1819  |  INIT_DEFERRABLE_WORK(&tbl->managed_work, neigh_managed_work);
1820  | 	queue_delayed_work(system_power_efficient_wq, &tbl->managed_work, 0);
1821  |
1822  |  timer_setup(&tbl->proxy_timer, neigh_proxy_process, 0);
1823  | 	skb_queue_head_init_class(&tbl->proxy_queue,
1824  | 			&neigh_table_proxy_queue_class);
1825  |
1826  | 	tbl->last_flush = now;
1827  | 	tbl->last_rand	= now + tbl->parms.reachable_time * 20;
1828  |
1829  | 	neigh_tables[index] = tbl;
1830  | }

Analysis:
- Decision: NotABug
- Reason: The warning points to size_t size = (1 << shift) * sizeof(struct neighbour *); where the shift is indeed performed in 32-bit int width because the literal 1 is an int. However, this does not constitute the target bug pattern nor a real bug here:

  - Target pattern requires a 32-bit shift whose result is then widened to 64-bit, causing truncation/overflow before assignment (e.g., assigning to u64). In this code, the shift result is then multiplied by sizeof(pointer) and assigned to size_t. While size_t is 64-bit on 64-bit platforms, the critical issue (loss of high bits due to 32-bit shift) would require shift ≥ 31, which is not feasible in this context.

  - Feasibility/bounds: shift is the log2 of the number of hash buckets for the neighbour table. It is initialized small (e.g., neigh_table_init uses neigh_hash_alloc(3)) and, in practice, is bounded by neighbour table sizing policies (gc thresholds, memory limits, and growth heuristics). Realistic shifts remain far below 31; allocating 2^31 buckets is impossible under the kernel’s memory constraints and far beyond configured neighbour table sizes. Thus, (1 << shift) never overflows 32-bit int in real scenarios, and there is no truncation before the multiplication/assignment.

  - Even on 64-bit systems, the shift result is safely within 32-bit for all practical values of shift in this code, so there is no loss of information that a pre-shift cast would prevent. On 32-bit systems, size_t is 32-bit anyway, so the warning’s 64-bit widening premise does not apply.

  - While a stylistic change like using (size_t)1 << shift or sizeof(struct neighbour *) << shift would silence the warning and is harmless, it is not required to fix a real bug.

Given the constraints and usage in the neighbour table, this is a false positive with respect to the specified bug pattern and not a real defect.

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

// No custom program states needed
// REGISTER_MAP_WITH_PROGRAMSTATE(...) not required

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PreStmt<ReturnStmt>,
        check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Narrow shift widened to 64-bit", "Integer")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      void analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                       CheckerContext &C, StringRef Ctx) const;

      static const BinaryOperator *findShiftInTree(const Stmt *S);
      static bool hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx);
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

  // Look for any explicit cast to integer type with width >= 64 within E's subtree.
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
    } else {
      if (const BinaryOperator *B = asShift(Child)) {
        (void)B; // not needed here
      }
      // Continue traversal for safety
      if (const BinaryOperator *B2 = findShiftInTree(Child)) {
        (void)B2;
      }
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

  // Find a left-shift operator within the expression tree.
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

  // If LHS type is already 64-bit (or wider), no issue.
  if (L->getType()->isIntegerType()) {
    unsigned LHSW = ACtx.getIntWidth(L->getType());
    if (LHSW >= 64)
      return;

    // If there is an explicit cast to >=64-bit within the LHS subtree, suppress.
    if (hasExplicitCastToWide64(L, ACtx))
      return;

    // Try to evaluate RHS; if it's a constant less than LHS width, suppress to reduce FPs.
    llvm::APSInt RHSEval;
    if (EvaluateExprToInt(RHSEval, R, C)) {
      // Treat negative or very large values conservatively.
      if (!RHSEval.isSigned() || !RHSEval.isNegative()) {
        uint64_t ShiftAmt = RHSEval.getZExtValue();
        if (ShiftAmt < LHSW) {
          // Heuristic suppression per plan.
          return;
        }
      }
    }
  } else {
    // Non-integer LHS shouldn't happen for <<, but be safe.
    return;
  }

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
  // Only handle assignments: LHS = RHS;
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
