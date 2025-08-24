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

Computing a size using 32-bit arithmetic and only then assigning it to a 64-bit variable, causing overflow before the assignment. Specifically, multiplying two 32-bit operands (e.g., u32 mall_size_per_umc and u32 num_umc) without promoting to 64-bit first:

u64 total = (u32)a * (u32)b;  // overflow happens in 32-bit
// Correct:
u64 total = (u64)a * b;  // force 64-bit arithmetic before assignment

This pattern arises when size/count calculations use narrower integer types for intermediate arithmetic even though the result is stored in a wider type.

The patch that needs to be detected:

## Patch Description

drm/amdgu: fix Unintentional integer overflow for mall size

Potentially overflowing expression mall_size_per_umc * adev->gmc.num_umc with type unsigned int (32 bits, unsigned)
is evaluated using 32-bit arithmetic,and then used in a context that expects an expression of type u64 (64 bits, unsigned).

Signed-off-by: Jesse Zhang <Jesse.Zhang@amd.com>
Reviewed-by: Christian König <christian.koenig@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>

## Buggy Code

```c
// Function: amdgpu_discovery_get_mall_info in drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
static int amdgpu_discovery_get_mall_info(struct amdgpu_device *adev)
{
	struct binary_header *bhdr;
	union mall_info *mall_info;
	u32 u, mall_size_per_umc, m_s_present, half_use;
	u64 mall_size;
	u16 offset;

	if (!adev->mman.discovery_bin) {
		DRM_ERROR("ip discovery uninitialized\n");
		return -EINVAL;
	}

	bhdr = (struct binary_header *)adev->mman.discovery_bin;
	offset = le16_to_cpu(bhdr->table_list[MALL_INFO].offset);

	if (!offset)
		return 0;

	mall_info = (union mall_info *)(adev->mman.discovery_bin + offset);

	switch (le16_to_cpu(mall_info->v1.header.version_major)) {
	case 1:
		mall_size = 0;
		mall_size_per_umc = le32_to_cpu(mall_info->v1.mall_size_per_m);
		m_s_present = le32_to_cpu(mall_info->v1.m_s_present);
		half_use = le32_to_cpu(mall_info->v1.m_half_use);
		for (u = 0; u < adev->gmc.num_umc; u++) {
			if (m_s_present & (1 << u))
				mall_size += mall_size_per_umc * 2;
			else if (half_use & (1 << u))
				mall_size += mall_size_per_umc / 2;
			else
				mall_size += mall_size_per_umc;
		}
		adev->gmc.mall_size = mall_size;
		adev->gmc.m_half_use = half_use;
		break;
	case 2:
		mall_size_per_umc = le32_to_cpu(mall_info->v2.mall_size_per_umc);
		adev->gmc.mall_size = mall_size_per_umc * adev->gmc.num_umc;
		break;
	default:
		dev_err(adev->dev,
			"Unhandled MALL info table %d.%d\n",
			le16_to_cpu(mall_info->v1.header.version_major),
			le16_to_cpu(mall_info->v1.header.version_minor));
		return -EINVAL;
	}
	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
index 87b31ed8de19..c71356cb393d 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
@@ -1629,7 +1629,7 @@ static int amdgpu_discovery_get_mall_info(struct amdgpu_device *adev)
 		break;
 	case 2:
 		mall_size_per_umc = le32_to_cpu(mall_info->v2.mall_size_per_umc);
-		adev->gmc.mall_size = mall_size_per_umc * adev->gmc.num_umc;
+		adev->gmc.mall_size = (uint64_t)mall_size_per_umc * adev->gmc.num_umc;
 		break;
 	default:
 		dev_err(adev->dev,
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/mm/slub.c
---|---
Warning:| line 4752, column 25
32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit
before the multiply

### Annotated Source Code


183   |  */
184   |
185   | /*
186   |  * We could simply use migrate_disable()/enable() but as long as it's a
187   |  * function call even on !PREEMPT_RT, use inline preempt_disable() there.
188   |  */
189   | #ifndef CONFIG_PREEMPT_RT
190   | #define slub_get_cpu_ptr(var) get_cpu_ptr(var)
191   | #define slub_put_cpu_ptr(var) put_cpu_ptr(var)
192   | #define USE_LOCKLESS_FAST_PATH()	(true)
193   | #else
194   | #define slub_get_cpu_ptr(var)		\
195   | ({					\
196   |  migrate_disable();		\
197   |  this_cpu_ptr(var);		\
198   | })
199   | #define slub_put_cpu_ptr(var)		\
200   | do {					\
201   |  (void)(var);			\
202   |  migrate_enable();		\
203   | } while (0)
204   | #define USE_LOCKLESS_FAST_PATH()	(false)
205   | #endif
206   |
207   | #ifndef CONFIG_SLUB_TINY
208   | #define __fastpath_inline __always_inline
209   | #else
210   | #define __fastpath_inline
211   | #endif
212   |
213   | #ifdef CONFIG_SLUB_DEBUG
214   | #ifdef CONFIG_SLUB_DEBUG_ON
215   | DEFINE_STATIC_KEY_TRUE(slub_debug_enabled);
216   | #else
217   | DEFINE_STATIC_KEY_FALSE(slub_debug_enabled);
218   | #endif
219   | #endif		/* CONFIG_SLUB_DEBUG */
220   |
221   | /* Structure holding parameters for get_partial() call chain */
222   | struct partial_context {
223   | 	gfp_t flags;
224   |  unsigned int orig_size;
225   |  void *object;
226   | };
227   |
228   | static inline bool kmem_cache_debug(struct kmem_cache *s)
229   | {
230   |  return kmem_cache_debug_flags(s, SLAB_DEBUG_FLAGS);
231   | }
232   |
233   | static inline bool slub_debug_orig_size(struct kmem_cache *s)
234   | {
235   |  return (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
236   | 			(s->flags & SLAB_KMALLOC));
237   | }
238   |
239   | void *fixup_red_left(struct kmem_cache *s, void *p)
240   | {
241   |  if (kmem_cache_debug_flags(s, SLAB_RED_ZONE))
242   | 		p += s->red_left_pad;
243   |
244   |  return p;
245   | }
246   |
247   | static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
248   | {
249   | #ifdef CONFIG_SLUB_CPU_PARTIAL
250   |  return !kmem_cache_debug(s);
251   | #else
252   |  return false;
253   | #endif
254   | }
255   |
256   | /*
257   |  * Issues still to be resolved:
258   |  *
259   |  * - Support PAGE_ALLOC_DEBUG. Should be easy to do.
260   |  *
261   |  * - Variable sizing of the per node arrays
262   |  */
263   |
264   | /* Enable to log cmpxchg failures */
265   | #undef SLUB_DEBUG_CMPXCHG
536   |  unsigned long freepointer_addr;
537   | 	freeptr_t p;
538   |
539   |  if (!debug_pagealloc_enabled_static())
540   |  return get_freepointer(s, object);
541   |
542   | 	object = kasan_reset_tag(object);
543   | 	freepointer_addr = (unsigned long)object + s->offset;
544   | 	copy_from_kernel_nofault(&p, (freeptr_t *)freepointer_addr, sizeof(p));
545   |  return freelist_ptr_decode(s, p, freepointer_addr);
546   | }
547   |
548   | static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
549   | {
550   |  unsigned long freeptr_addr = (unsigned long)object + s->offset;
551   |
552   | #ifdef CONFIG_SLAB_FREELIST_HARDENED
553   |  BUG_ON(object == fp); /* naive detection of double free or corruption */
554   | #endif
555   |
556   | 	freeptr_addr = (unsigned long)kasan_reset_tag((void *)freeptr_addr);
557   | 	*(freeptr_t *)freeptr_addr = freelist_ptr_encode(s, fp, freeptr_addr);
558   | }
559   |
560   | /*
561   |  * See comment in calculate_sizes().
562   |  */
563   | static inline bool freeptr_outside_object(struct kmem_cache *s)
564   | {
565   |  return s->offset >= s->inuse;
566   | }
567   |
568   | /*
569   |  * Return offset of the end of info block which is inuse + free pointer if
570   |  * not overlapping with object.
571   |  */
572   | static inline unsigned int get_info_end(struct kmem_cache *s)
573   | {
574   |  if (freeptr_outside_object(s))
575   |  return s->inuse + sizeof(void *);
576   |  else
577   |  return s->inuse;
578   | }
579   |
580   | /* Loop over all objects in a slab */
581   | #define for_each_object(__p, __s, __addr, __objects) \
582   |  for (__p = fixup_red_left(__s, __addr); \
583   |  __p < (__addr) + (__objects) * (__s)->size; \
584   |  __p += (__s)->size)
585   |
586   | static inline unsigned int order_objects(unsigned int order, unsigned int size)
587   | {
588   |  return ((unsigned int)PAGE_SIZE << order) / size;
589   | }
590   |
591   | static inline struct kmem_cache_order_objects oo_make(unsigned int order,
592   |  unsigned int size)
593   | {
594   |  struct kmem_cache_order_objects x = {
595   | 		(order << OO_SHIFT) + order_objects(order, size)
596   | 	};
597   |
598   |  return x;
599   | }
600   |
601   | static inline unsigned int oo_order(struct kmem_cache_order_objects x)
602   | {
603   |  return x.x >> OO_SHIFT;
604   | }
605   |
606   | static inline unsigned int oo_objects(struct kmem_cache_order_objects x)
607   | {
608   |  return x.x & OO_MASK;
609   | }
610   |
611   | #ifdef CONFIG_SLUB_CPU_PARTIAL
612   | static void slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
613   | {
614   |  unsigned int nr_slabs;
615   |
616   | 	s->cpu_partial = nr_objects;
617   |
618   |  /*
1794  |  /* Found a block that has a slab list, search it */
1795  |  while (*iter) {
1796  |  char *end, *glob;
1797  | 			size_t cmplen;
1798  |
1799  | 			end = strchrnul(iter, ',');
1800  |  if (next_block && next_block < end)
1801  | 				end = next_block - 1;
1802  |
1803  | 			glob = strnchr(iter, end - iter, '*');
1804  |  if (glob)
1805  | 				cmplen = glob - iter;
1806  |  else
1807  | 				cmplen = max_t(size_t, len, (end - iter));
1808  |
1809  |  if (!strncmp(name, iter, cmplen)) {
1810  | 				flags |= block_flags;
1811  |  return flags;
1812  | 			}
1813  |
1814  |  if (!*end || *end == ';')
1815  |  break;
1816  | 			iter = end + 1;
1817  | 		}
1818  | 	}
1819  |
1820  |  return flags | slub_debug_local;
1821  | }
1822  | #else /* !CONFIG_SLUB_DEBUG */
1823  | static inline void setup_object_debug(struct kmem_cache *s, void *object) {}
1824  | static inline
1825  | void setup_slab_debug(struct kmem_cache *s, struct slab *slab, void *addr) {}
1826  |
1827  | static inline bool alloc_debug_processing(struct kmem_cache *s,
1828  |  struct slab *slab, void *object, int orig_size) { return true; }
1829  |
1830  | static inline bool free_debug_processing(struct kmem_cache *s,
1831  |  struct slab *slab, void *head, void *tail, int *bulk_cnt,
1832  |  unsigned long addr, depot_stack_handle_t handle) { return true; }
1833  |
1834  | static inline void slab_pad_check(struct kmem_cache *s, struct slab *slab) {}
1835  | static inline int check_object(struct kmem_cache *s, struct slab *slab,
1836  |  void *object, u8 val) { return 1; }
1837  | static inline depot_stack_handle_t set_track_prepare(void) { return 0; }
1838  | static inline void set_track(struct kmem_cache *s, void *object,
1839  |  enum track_item alloc, unsigned long addr) {}
1840  | static inline void add_full(struct kmem_cache *s, struct kmem_cache_node *n,
1841  |  struct slab *slab) {}
1842  | static inline void remove_full(struct kmem_cache *s, struct kmem_cache_node *n,
1843  |  struct slab *slab) {}
1844  | slab_flags_t kmem_cache_flags(slab_flags_t flags, const char *name)
1845  | {
1846  |  return flags;
1847  | }
1848  | #define slub_debug 0
1849  |
1850  | #define disable_higher_order_debug 0
1851  |
1852  | static inline unsigned long node_nr_slabs(struct kmem_cache_node *n)
1853  | 							{ return 0; }
1854  | static inline void inc_slabs_node(struct kmem_cache *s, int node,
1855  |  int objects) {}
1856  | static inline void dec_slabs_node(struct kmem_cache *s, int node,
1857  |  int objects) {}
1858  |
1859  | #ifndef CONFIG_SLUB_TINY
1860  | static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
1861  |  void **freelist, void *nextfree)
1862  | {
1863  |  return false;
1864  | }
1865  | #endif
1866  | #endif /* CONFIG_SLUB_DEBUG */
1867  |
1868  | static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
1869  | {
1870  |  return (s->flags & SLAB_RECLAIM_ACCOUNT) ?
1871  | 		NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
1872  | }
1873  |
1874  | #ifdef CONFIG_MEMCG_KMEM
1875  | static inline void memcg_free_slab_cgroups(struct slab *slab)
1876  | {
4672  | static unsigned int slub_min_order;
4673  | static unsigned int slub_max_order =
4674  |  IS_ENABLED(CONFIG_SLUB_TINY) ? 1 : PAGE_ALLOC_COSTLY_ORDER;
4675  | static unsigned int slub_min_objects;
4676  |
4677  | /*
4678  |  * Calculate the order of allocation given an slab object size.
4679  |  *
4680  |  * The order of allocation has significant impact on performance and other
4681  |  * system components. Generally order 0 allocations should be preferred since
4682  |  * order 0 does not cause fragmentation in the page allocator. Larger objects
4683  |  * be problematic to put into order 0 slabs because there may be too much
4684  |  * unused space left. We go to a higher order if more than 1/16th of the slab
4685  |  * would be wasted.
4686  |  *
4687  |  * In order to reach satisfactory performance we must ensure that a minimum
4688  |  * number of objects is in one slab. Otherwise we may generate too much
4689  |  * activity on the partial lists which requires taking the list_lock. This is
4690  |  * less a concern for large slabs though which are rarely used.
4691  |  *
4692  |  * slab_max_order specifies the order where we begin to stop considering the
4693  |  * number of objects in a slab as critical. If we reach slab_max_order then
4694  |  * we try to keep the page order as low as possible. So we accept more waste
4695  |  * of space in favor of a small page order.
4696  |  *
4697  |  * Higher order allocations also allow the placement of more objects in a
4698  |  * slab and thereby reduce object handling overhead. If the user has
4699  |  * requested a higher minimum order then we start with that one instead of
4700  |  * the smallest order which will fit the object.
4701  |  */
4702  | static inline unsigned int calc_slab_order(unsigned int size,
4703  |  unsigned int min_order, unsigned int max_order,
4704  |  unsigned int fract_leftover)
4705  | {
4706  |  unsigned int order;
4707  |
4708  |  for (order = min_order; order <= max_order; order++) {
4709  |
4710  |  unsigned int slab_size = (unsigned int)PAGE_SIZE << order;
4711  |  unsigned int rem;
4712  |
4713  | 		rem = slab_size % size;
4714  |
4715  |  if (rem <= slab_size / fract_leftover)
4716  |  break;
4717  | 	}
4718  |
4719  |  return order;
4720  | }
4721  |
4722  | static inline int calculate_order(unsigned int size)
4723  | {
4724  |  unsigned int order;
4725  |  unsigned int min_objects;
4726  |  unsigned int max_objects;
4727  |  unsigned int min_order;
4728  |
4729  | 	min_objects = slub_min_objects;
4730  |  if (!min_objects) {
    5←Assuming 'min_objects' is not equal to 0→
    6←Taking false branch→
4731  |  /*
4732  |  * Some architectures will only update present cpus when
4733  |  * onlining them, so don't trust the number if it's just 1. But
4734  |  * we also don't want to use nr_cpu_ids always, as on some other
4735  |  * architectures, there can be many possible cpus, but never
4736  |  * onlined. Here we compromise between trying to avoid too high
4737  |  * order on systems that appear larger than they are, and too
4738  |  * low order on systems that appear smaller than they are.
4739  |  */
4740  |  unsigned int nr_cpus = num_present_cpus();
4741  |  if (nr_cpus <= 1)
4742  | 			nr_cpus = nr_cpu_ids;
4743  | 		min_objects = 4 * (fls(nr_cpus) + 1);
4744  | 	}
4745  |  /* min_objects can't be 0 because get_order(0) is undefined */
4746  |  max_objects = max(order_objects(slub_max_order, size), 1U);
    7←Assuming '__UNIQUE_ID___x1570' is > '__UNIQUE_ID___y1571'→
    8←'?' condition is true→
4747  |  min_objects = min(min_objects, max_objects);
    9←Assuming '__UNIQUE_ID___x1572' is >= '__UNIQUE_ID___y1573'→
    10←'?' condition is false→
4748  |
4749  | 	min_order = max_t(unsigned int, slub_min_order,
    11←Assuming '__UNIQUE_ID___x1574' is <= '__UNIQUE_ID___y1575'→
    12←'?' condition is false→
4750  |  get_order(min_objects * size));
4751  |  if (order_objects(min_order, size) > MAX_OBJS_PER_PAGE)
    13←Assuming the condition is true→
    14←Taking true branch→
4752  |  return get_order(size * MAX_OBJS_PER_PAGE) - 1;
    15←32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply
4753  |
4754  |  /*
4755  |  * Attempt to find best configuration for a slab. This works by first
4756  |  * attempting to generate a layout with the best possible configuration
4757  |  * and backing off gradually.
4758  |  *
4759  |  * We start with accepting at most 1/16 waste and try to find the
4760  |  * smallest order from min_objects-derived/slab_min_order up to
4761  |  * slab_max_order that will satisfy the constraint. Note that increasing
4762  |  * the order can only result in same or less fractional waste, not more.
4763  |  *
4764  |  * If that fails, we increase the acceptable fraction of waste and try
4765  |  * again. The last iteration with fraction of 1/2 would effectively
4766  |  * accept any waste and give us the order determined by min_objects, as
4767  |  * long as at least single object fits within slab_max_order.
4768  |  */
4769  |  for (unsigned int fraction = 16; fraction > 1; fraction /= 2) {
4770  | 		order = calc_slab_order(size, min_order, slub_max_order,
4771  | 					fraction);
4772  |  if (order <= slub_max_order)
4773  |  return order;
4774  | 	}
4775  |
4776  |  /*
4777  |  * Doh this slab cannot be placed using slab_max_order.
4778  |  */
4779  | 	order = get_order(size);
4780  |  if (order <= MAX_PAGE_ORDER)
4781  |  return order;
4782  |  return -ENOSYS;
4904  |  GFP_KERNEL, node);
4905  |
4906  |  if (!n) {
4907  | 			free_kmem_cache_nodes(s);
4908  |  return 0;
4909  | 		}
4910  |
4911  | 		init_kmem_cache_node(n);
4912  | 		s->node[node] = n;
4913  | 	}
4914  |  return 1;
4915  | }
4916  |
4917  | static void set_cpu_partial(struct kmem_cache *s)
4918  | {
4919  | #ifdef CONFIG_SLUB_CPU_PARTIAL
4920  |  unsigned int nr_objects;
4921  |
4922  |  /*
4923  |  * cpu_partial determined the maximum number of objects kept in the
4924  |  * per cpu partial lists of a processor.
4925  |  *
4926  |  * Per cpu partial lists mainly contain slabs that just have one
4927  |  * object freed. If they are used for allocation then they can be
4928  |  * filled up again with minimal effort. The slab will never hit the
4929  |  * per node partial lists and therefore no locking will be required.
4930  |  *
4931  |  * For backwards compatibility reasons, this is determined as number
4932  |  * of objects, even though we now limit maximum number of pages, see
4933  |  * slub_set_cpu_partial()
4934  |  */
4935  |  if (!kmem_cache_has_cpu_partial(s))
4936  | 		nr_objects = 0;
4937  |  else if (s->size >= PAGE_SIZE)
4938  | 		nr_objects = 6;
4939  |  else if (s->size >= 1024)
4940  | 		nr_objects = 24;
4941  |  else if (s->size >= 256)
4942  | 		nr_objects = 52;
4943  |  else
4944  | 		nr_objects = 120;
4945  |
4946  | 	slub_set_cpu_partial(s, nr_objects);
4947  | #endif
4948  | }
4949  |
4950  | /*
4951  |  * calculate_sizes() determines the order and the distribution of data within
4952  |  * a slab object.
4953  |  */
4954  | static int calculate_sizes(struct kmem_cache *s)
4955  | {
4956  |  slab_flags_t flags = s->flags;
4957  |  unsigned int size = s->object_size;
4958  |  unsigned int order;
4959  |
4960  |  /*
4961  |  * Round up object size to the next word boundary. We can only
4962  |  * place the free pointer at word boundaries and this determines
4963  |  * the possible location of the free pointer.
4964  |  */
4965  | 	size = ALIGN(size, sizeof(void *));
4966  |
4967  | #ifdef CONFIG_SLUB_DEBUG
4968  |  /*
4969  |  * Determine if we can poison the object itself. If the user of
4970  |  * the slab may touch the object after free or before allocation
4971  |  * then we should never poison the object itself.
4972  |  */
4973  |  if ((flags & SLAB_POISON) && !(flags & SLAB_TYPESAFE_BY_RCU) &&
4974  | 			!s->ctor)
4975  | 		s->flags |= __OBJECT_POISON;
4976  |  else
4977  | 		s->flags &= ~__OBJECT_POISON;
4978  |
4979  |
4980  |  /*
4981  |  * If we are Redzoning then check if there is some space between the
4982  |  * end of the object and the free pointer. If not then add an
4983  |  * additional word to have some bytes to store Redzone information.
4984  |  */
4985  |  if ((flags & SLAB_RED_ZONE) && size == s->object_size)
4986  | 		size += sizeof(void *);
4987  | #endif
4988  |
4989  |  /*
4990  |  * With that we have determined the number of bytes in actual use
4991  |  * by the object and redzoning.
4992  |  */
4993  | 	s->inuse = size;
4994  |
4995  |  if (slub_debug_orig_size(s) ||
4996  | 	    (flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
    3←Assuming the condition is true→
4997  | 	    ((flags & SLAB_RED_ZONE) && s->object_size < sizeof(void *)) ||
4998  | 	    s->ctor) {
4999  |  /*
5000  |  * Relocate free pointer after the object if it is not
5001  |  * permitted to overwrite the first word of the object on
5002  |  * kmem_cache_free.
5003  |  *
5004  |  * This is the case if we do RCU, have a constructor or
5005  |  * destructor, are poisoning the objects, or are
5006  |  * redzoning an object smaller than sizeof(void *).
5007  |  *
5008  |  * The assumption that s->offset >= s->inuse means free
5009  |  * pointer is outside of the object is used in the
5010  |  * freeptr_outside_object() function. If that is no
5011  |  * longer true, the function needs to be modified.
5012  |  */
5013  |  s->offset = size;
5014  |  size += sizeof(void *);
5015  | 	} else {
5016  |  /*
5017  |  * Store freelist pointer near middle of object to keep
5018  |  * it away from the edges of the object to avoid small
5019  |  * sized over/underflows from neighboring allocations.
5020  |  */
5021  | 		s->offset = ALIGN_DOWN(s->object_size / 2, sizeof(void *));
5022  | 	}
5023  |
5024  | #ifdef CONFIG_SLUB_DEBUG
5025  |  if (flags & SLAB_STORE_USER) {
5026  |  /*
5027  |  * Need to store information about allocs and frees after
5028  |  * the object.
5029  |  */
5030  | 		size += 2 * sizeof(struct track);
5031  |
5032  |  /* Save the original kmalloc request size */
5033  |  if (flags & SLAB_KMALLOC)
5034  | 			size += sizeof(unsigned int);
5035  | 	}
5036  | #endif
5037  |
5038  |  kasan_cache_create(s, &size, &s->flags);
5039  | #ifdef CONFIG_SLUB_DEBUG
5040  |  if (flags & SLAB_RED_ZONE) {
5041  |  /*
5042  |  * Add some empty padding so that we can catch
5043  |  * overwrites from earlier objects rather than let
5044  |  * tracking information or the free pointer be
5045  |  * corrupted if a user writes before the start
5046  |  * of the object.
5047  |  */
5048  | 		size += sizeof(void *);
5049  |
5050  | 		s->red_left_pad = sizeof(void *);
5051  | 		s->red_left_pad = ALIGN(s->red_left_pad, s->align);
5052  | 		size += s->red_left_pad;
5053  | 	}
5054  | #endif
5055  |
5056  |  /*
5057  |  * SLUB stores one object immediately after another beginning from
5058  |  * offset 0. In order to align the objects we have to simply size
5059  |  * each object to conform to the alignment.
5060  |  */
5061  | 	size = ALIGN(size, s->align);
5062  | 	s->size = size;
5063  | 	s->reciprocal_size = reciprocal_value(size);
5064  |  order = calculate_order(size);
    4←Calling 'calculate_order'→
5065  |
5066  |  if ((int)order < 0)
5067  |  return 0;
5068  |
5069  | 	s->allocflags = 0;
5070  |  if (order)
5071  | 		s->allocflags |= __GFP_COMP;
5072  |
5073  |  if (s->flags & SLAB_CACHE_DMA)
5074  | 		s->allocflags |= GFP_DMA;
5075  |
5076  |  if (s->flags & SLAB_CACHE_DMA32)
5077  | 		s->allocflags |= GFP_DMA32;
5078  |
5079  |  if (s->flags & SLAB_RECLAIM_ACCOUNT)
5080  | 		s->allocflags |= __GFP_RECLAIMABLE;
5081  |
5082  |  /*
5083  |  * Determine the number of objects per slab
5084  |  */
5085  | 	s->oo = oo_make(order, size);
5086  | 	s->min = oo_make(get_order(size), size);
5087  |
5088  |  return !!oo_objects(s->oo);
5089  | }
5090  |
5091  | static int kmem_cache_open(struct kmem_cache *s, slab_flags_t flags)
5092  | {
5093  |  s->flags = kmem_cache_flags(flags, s->name);
5094  | #ifdef CONFIG_SLAB_FREELIST_HARDENED
5095  | 	s->random = get_random_long();
5096  | #endif
5097  |
5098  |  if (!calculate_sizes(s))
    2←Calling 'calculate_sizes'→
5099  |  goto error;
5100  |  if (disable_higher_order_debug) {
5101  |  /*
5102  |  * Disable debugging flags that store metadata if the min slab
5103  |  * order increased.
5104  |  */
5105  |  if (get_order(s->size) > get_order(s->object_size)) {
5106  | 			s->flags &= ~DEBUG_METADATA_FLAGS;
5107  | 			s->offset = 0;
5108  |  if (!calculate_sizes(s))
5109  |  goto error;
5110  | 		}
5111  | 	}
5112  |
5113  | #ifdef system_has_freelist_aba
5114  |  if (system_has_freelist_aba() && !(s->flags & SLAB_NO_CMPXCHG)) {
5115  |  /* Enable fast mode */
5116  | 		s->flags |= __CMPXCHG_DOUBLE;
5117  | 	}
5118  | #endif
5119  |
5120  |  /*
5121  |  * The larger the object size is, the more slabs we want on the partial
5122  |  * list to avoid pounding the page allocator excessively.
5123  |  */
5124  | 	s->min_partial = min_t(unsigned long, MAX_PARTIAL, ilog2(s->size) / 2);
5125  | 	s->min_partial = max_t(unsigned long, MIN_PARTIAL, s->min_partial);
5126  |
5127  | 	set_cpu_partial(s);
5128  |
5652  | 	kmem_cache_node = bootstrap(&boot_kmem_cache_node);
5653  |
5654  |  /* Now we can use the kmem_cache to allocate kmalloc slabs */
5655  | 	setup_kmalloc_cache_index_table();
5656  | 	create_kmalloc_caches();
5657  |
5658  |  /* Setup random freelists for each cache */
5659  | 	init_freelist_randomization();
5660  |
5661  | 	cpuhp_setup_state_nocalls(CPUHP_SLUB_DEAD, "slub:dead", NULL,
5662  | 				  slub_cpu_dead);
5663  |
5664  |  pr_info("SLUB: HWalign=%d, Order=%u-%u, MinObjects=%u, CPUs=%u, Nodes=%u\n",
5665  |  cache_line_size(),
5666  |  slub_min_order, slub_max_order, slub_min_objects,
5667  |  nr_cpu_ids, nr_node_ids);
5668  | }
5669  |
5670  | void __init kmem_cache_init_late(void)
5671  | {
5672  | #ifndef CONFIG_SLUB_TINY
5673  | 	flushwq = alloc_workqueue("slub_flushwq", WQ_MEM_RECLAIM, 0);
5674  |  WARN_ON(!flushwq);
5675  | #endif
5676  | }
5677  |
5678  | struct kmem_cache *
5679  | __kmem_cache_alias(const char *name, unsigned int size, unsigned int align,
5680  | 		   slab_flags_t flags, void (*ctor)(void *))
5681  | {
5682  |  struct kmem_cache *s;
5683  |
5684  | 	s = find_mergeable(size, align, flags, name, ctor);
5685  |  if (s) {
5686  |  if (sysfs_slab_alias(s, name))
5687  |  return NULL;
5688  |
5689  | 		s->refcount++;
5690  |
5691  |  /*
5692  |  * Adjust the object sizes so that we clear
5693  |  * the complete object on kzalloc.
5694  |  */
5695  | 		s->object_size = max(s->object_size, size);
5696  | 		s->inuse = max(s->inuse, ALIGN(size, sizeof(void *)));
5697  | 	}
5698  |
5699  |  return s;
5700  | }
5701  |
5702  | int __kmem_cache_create(struct kmem_cache *s, slab_flags_t flags)
5703  | {
5704  |  int err;
5705  |
5706  |  err = kmem_cache_open(s, flags);
    1Calling 'kmem_cache_open'→
5707  |  if (err)
5708  |  return err;
5709  |
5710  |  /* Mutex is not taken during early boot */
5711  |  if (slab_state <= UP)
5712  |  return 0;
5713  |
5714  | 	err = sysfs_slab_add(s);
5715  |  if (err) {
5716  | 		__kmem_cache_release(s);
5717  |  return err;
5718  | 	}
5719  |
5720  |  if (s->flags & SLAB_STORE_USER)
5721  | 		debugfs_slab_add(s);
5722  |
5723  |  return 0;
5724  | }
5725  |
5726  | #ifdef SLAB_SUPPORTS_SYSFS
5727  | static int count_inuse(struct slab *slab)
5728  | {
5729  |  return slab->inuse;
5730  | }
5731  |
5732  | static int count_total(struct slab *slab)
5733  | {
5734  |  return slab->objects;
5735  | }
5736  | #endif

Analysis:
- Decision: NotABug
- Reason: The warning points to size * MAX_OBJS_PER_PAGE in calculate_order(), claiming 32-bit multiplication that widens after the multiply. However:
  - This does not match the target pattern, which requires two 32-bit operands being multiplied with the result then assigned to a 64-bit variable (u64). Here, the product is passed to get_order(), not assigned to a u64.
  - More importantly, overflow is not feasible in this specific control flow. The branch is taken only when order_objects(min_order, size) > MAX_OBJS_PER_PAGE, i.e., ((PAGE_SIZE << min_order) / size) > MAX_OBJS_PER_PAGE. This implies size * MAX_OBJS_PER_PAGE < slab_size = ((unsigned int)PAGE_SIZE << min_order). Since slab_size is computed as an unsigned int, it is bounded by UINT_MAX, so size * MAX_OBJS_PER_PAGE < 2^32. Therefore, the 32-bit multiplication cannot overflow here.
  - Concretely, with MAX_OBJS_PER_PAGE typically 32767, for a 32-bit multiply to overflow you’d need size > floor(2^32 / 32767) ≈ 131072. But if size ≥ 131072, achieving order_objects(min_order, size) > 32767 would require slab_size > ~4.29 GB, which is impossible given slab_size is computed as a 32-bit value. Hence, the condition ensuring this path is taken simultaneously ensures the product fits in 32 bits.
  - Even on 64-bit architectures (where get_order takes an unsigned long), the multiplication still occurs safely in 32 bits due to the precondition above; there is no overflow before widening.

Given both the mismatch to the target bug pattern and the proven infeasibility of overflow on this path, this is a false positive and not a real bug.

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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided in the prompt (assumed available):
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

// Program state: Map constant-valued integer locals to their known values.
REGISTER_MAP_WITH_PROGRAMSTATE(ConstIntVarMap, const VarDecl *, llvm::APSInt)

namespace {

class SAGenTestChecker
    : public Checker<
          check::PostStmt<BinaryOperator>,
          check::PostStmt<DeclStmt>,
          check::Bind,
          check::RegionChanges> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "32-bit multiply widened to 64-bit",
                       "Integer Overflow")) {}

  void checkPostStmt(const BinaryOperator *B, CheckerContext &C) const;
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *Invalidated,
                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                     ArrayRef<const MemRegion *> Regions,
                                     const LocationContext *LCtx,
                                     const CallEvent *Call) const;

private:
  static unsigned getIntWidth(QualType T, CheckerContext &C) {
    return C.getASTContext().getIntWidth(T);
  }

  static bool isInt64OrWider(QualType T, CheckerContext &C) {
    return T->isIntegerType() && getIntWidth(T, C) >= 64;
  }

  static bool isIntegerType(const Expr *E) {
    if (!E) return false;
    return E->getType()->isIntegerType();
  }

  static const Expr *ignoreNoOps(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  static bool isNoOpWrapper(const Stmt *S) {
    return isa<ParenExpr>(S) || isa<ImplicitCastExpr>(S);
  }

  static bool isSizeT(QualType T, CheckerContext &C) {
    ASTContext &AC = C.getASTContext();
    return AC.hasSameType(AC.getCanonicalType(T),
                          AC.getCanonicalType(AC.getSizeType()));
  }

  static StringRef getRecordNameFromExprBase(const Expr *E) {
    if (!E) return StringRef();
    QualType QT = E->getType();
    if (const auto *PT = QT->getAs<PointerType>())
      QT = PT->getPointeeType();
    if (const auto *RT = QT->getAs<RecordType>()) {
      const RecordDecl *RD = RT->getDecl();
      if (const IdentifierInfo *II = RD->getIdentifier())
        return II->getName();
    }
    return StringRef();
  }

  static StringRef getDeclRefName(const Expr *E) {
    if (!E) return StringRef();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        return VD->getName();
    }
    return StringRef();
  }

  // Helpers to work with state-tracked constant ints.
  static bool getConstValueFromState(const Expr *E, CheckerContext &C,
                                     llvm::APSInt &Out) {
    const Expr *Core = ignoreNoOps(E);
    if (!Core)
      return false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(Core)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        ProgramStateRef St = C.getState();
        if (const llvm::APSInt *V = St->get<ConstIntVarMap>(VD)) {
          Out = *V;
          return true;
        }
      }
    }
    return false;
  }

  bool getImmediateNonTrivialParent(const Stmt *Child,
                                    CheckerContext &C,
                                    const Stmt *&OutParentStmt,
                                    const Decl *&OutParentDecl) const {
    OutParentStmt = nullptr;
    OutParentDecl = nullptr;
    if (!Child)
      return false;

    const Stmt *Cur = Child;
    while (true) {
      auto Parents = C.getASTContext().getParents(*Cur);
      if (Parents.empty())
        return false;

      const Stmt *PS = Parents[0].get<Stmt>();
      const Decl *PD = Parents[0].get<Decl>();

      if (PS) {
        if (isNoOpWrapper(PS)) {
          Cur = PS;
          continue;
        }
        OutParentStmt = PS;
        return true;
      } else if (PD) {
        OutParentDecl = PD;
        return true;
      } else {
        return false;
      }
    }
  }

  bool isDirectWidenedUseTo64(const Expr *Mul,
                              CheckerContext &C,
                              const Stmt *&UseSiteStmt,
                              const Decl *&UseSiteDecl) const {
    UseSiteStmt = nullptr;
    UseSiteDecl = nullptr;
    if (!Mul)
      return false;

    const Stmt *PStmt = nullptr;
    const Decl *PDecl = nullptr;
    if (!getImmediateNonTrivialParent(Mul, C, PStmt, PDecl))
      return false;

    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(PStmt)) {
      if (!BO->isAssignmentOp())
        return false;
      const Expr *LHS = BO->getLHS();
      if (LHS && isInt64OrWider(LHS->getType(), C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *CS = dyn_cast_or_null<CStyleCastExpr>(PStmt)) {
      QualType DestTy = CS->getTypeAsWritten();
      if (isInt64OrWider(DestTy, C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(PStmt)) {
      const auto *FD =
          dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
      if (FD && isInt64OrWider(FD->getReturnType(), C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *Call = dyn_cast_or_null<CallExpr>(PStmt)) {
      const FunctionDecl *FD = Call->getDirectCallee();
      if (!FD)
        return false;

      for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
        const Expr *Arg = Call->getArg(i)->IgnoreParenImpCasts();
        const Expr *MulCore = Mul->IgnoreParenImpCasts();
        if (Arg == MulCore) {
          QualType ParamTy = FD->getParamDecl(i)->getType();
          if (isInt64OrWider(ParamTy, C)) {
            UseSiteStmt = PStmt;
            return true;
          }
        }
      }
      return false;
    }

    if (const auto *VD = dyn_cast_or_null<VarDecl>(PDecl)) {
      if (isInt64OrWider(VD->getType(), C)) {
        UseSiteDecl = PDecl;
        return true;
      }
      return false;
    }

    return false;
  }

  // Domain-specific maxima to tighten bounds for known Linux patterns.
  bool getDomainSpecificMax(const Expr *E, CheckerContext &C,
                            llvm::APSInt &Out) const {
    if (!E) return false;
    const Expr *Core = E->IgnoreParenImpCasts();

    const auto *DRE = dyn_cast<DeclRefExpr>(Core);
    if (!DRE) return false;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD) return false;

    const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!FD) return false;

    StringRef FuncName = FD->getName();
    StringRef VarName = VD->getName();

    // PCI/MSI-X: msix_map_region(dev, unsigned int nr_entries)
    // nr_entries is derived from msix_table_size(control) with a spec-bound <= 2048.
    if (FuncName.equals("msix_map_region") && VarName.equals("nr_entries")) {
      Out = llvm::APSInt(llvm::APInt(32, 2048), /*isUnsigned=*/true);
      return true;
    }

    return false;
  }

  // Try to determine an upper bound for an expression.
  bool getMaxForExpr(const Expr *E, CheckerContext &C, llvm::APSInt &Out) const {
    if (!E) return false;

    E = E->IgnoreParenImpCasts();

    // Exact tracked constant?
    if (getConstValueFromState(E, C, Out))
      return true;

    // Domain-specific bound (e.g. nr_entries <= 2048 in msix_map_region).
    if (getDomainSpecificMax(E, C, Out))
      return true;

    // Constant evaluation?
    if (EvaluateExprToInt(Out, E, C))
      return true;

    // Simple folding for sum/difference to tighten bounds.
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->isAdditiveOp()) {
        llvm::APSInt LMax, RMax;
        bool HasL = getMaxForExpr(BO->getLHS(), C, LMax);
        bool HasR = getMaxForExpr(BO->getRHS(), C, RMax);
        if (HasL && HasR) {
          __int128 L = LMax.isSigned() ? (__int128)LMax.getExtValue()
                                       : (__int128)LMax.getZExtValue();
          __int128 R = RMax.isSigned() ? (__int128)RMax.getExtValue()
                                       : (__int128)RMax.getZExtValue();
          __int128 S = BO->getOpcode() == BO_Add ? (L + R) : (L - R);
          uint64_t UB = S < 0 ? 0 : (S > (__int128)UINT64_MAX ? UINT64_MAX : (uint64_t)S);
          Out = llvm::APSInt(llvm::APInt(64, UB), /*isUnsigned=*/true);
          return true;
        }
      }
    }

    // Symbolic maximum?
    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(E, C.getLocationContext());
    SymbolRef Sym = V.getAsSymbol();
    if (Sym) {
      if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
        Out = *MaxV;
        return true;
      }
    }

    // Fallback: type-based maximum
    QualType QT = E->getType();
    if (!QT->isIntegerType())
      return false;

    unsigned W = getIntWidth(QT, C);
    bool IsUnsigned = QT->isUnsignedIntegerType();
    if (W == 0)
      return false;

    if (IsUnsigned) {
      Out = llvm::APSInt::getMaxValue(W, /*isUnsigned=*/true);
    } else {
      Out = llvm::APSInt::getMaxValue(W, /*isUnsigned=*/false);
    }
    return true;
  }

  // Check if we can prove the product fits into the narrower arithmetic width.
  bool productDefinitelyFits(const BinaryOperator *B, CheckerContext &C) const {
    if (!B) return false;
    const Expr *LHS = B->getLHS();
    const Expr *RHS = B->getRHS();
    if (!LHS || !RHS)
      return false;

    llvm::APSInt MaxL, MaxR;
    if (!getMaxForExpr(LHS, C, MaxL) || !getMaxForExpr(RHS, C, MaxR))
      return false; // Can't prove, so not definitely safe.

    // Compute conservatively using 128-bit.
    uint64_t ML = MaxL.isSigned() ? (uint64_t)MaxL.getExtValue() : MaxL.getZExtValue();
    uint64_t MR = MaxR.isSigned() ? (uint64_t)MaxR.getExtValue() : MaxR.getZExtValue();
    __uint128_t Prod = ((__uint128_t)ML) * ((__uint128_t)MR);

    // Determine limit for the arithmetic type of the multiply.
    unsigned MulW = getIntWidth(B->getType(), C);
    bool IsUnsignedMul = B->getType()->isUnsignedIntegerType();

    if (MulW >= 64) {
      return true;
    }

    __uint128_t Limit;
    if (IsUnsignedMul) {
      Limit = (((__uint128_t)1) << MulW) - 1;
    } else {
      // Signed max: 2^(W-1) - 1
      Limit = (((__uint128_t)1) << (MulW - 1)) - 1;
    }

    return Prod <= Limit;
  }

  bool containsAnyName(const Expr *E, CheckerContext &C,
                       std::initializer_list<StringRef> Needles) const {
    if (!E) return false;
    for (StringRef N : Needles) {
      if (ExprHasName(E, N, C))
        return true;
    }
    return false;
  }

  bool containsAnyNameInString(StringRef S,
                               std::initializer_list<StringRef> Needles) const {
    for (StringRef N : Needles) {
      if (S.contains(N))
        return true;
    }
    return false;
  }

  bool looksLikeSizeContext(const Stmt *UseSiteStmt,
                            const Decl *UseSiteDecl,
                            const BinaryOperator *Mul,
                            CheckerContext &C) const {
    static const std::initializer_list<StringRef> Positives = {
        "size", "len", "length", "count", "num", "bytes", "capacity", "total", "sz"
    };
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt)) {
      if (BO->isAssignmentOp()) {
        const Expr *LHS = BO->getLHS();
        if (LHS && containsAnyName(LHS, C, Positives))
          return true;
      }
    }
    if (const auto *VD = dyn_cast_or_null<VarDecl>(UseSiteDecl)) {
      if (containsAnyNameInString(VD->getName(), Positives))
        return true;
    }
    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(UseSiteStmt)) {
      if (const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl())) {
        if (containsAnyNameInString(FD->getName(), Positives))
          return true;
      }
      if (Mul) {
        if (containsAnyName(Mul->getLHS(), C, Positives) ||
            containsAnyName(Mul->getRHS(), C, Positives))
          return true;
      }
    }
    if (const auto *Call = dyn_cast_or_null<CallExpr>(UseSiteStmt)) {
      if (const FunctionDecl *FD = Call->getDirectCallee()) {
        for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
          const Expr *Arg = Call->getArg(i)->IgnoreParenImpCasts();
          const Expr *MulCore = Mul ? Mul->IgnoreParenImpCasts() : nullptr;
          if (Arg == MulCore) {
            StringRef PName = FD->getParamDecl(i)->getName();
            if (containsAnyNameInString(PName, Positives))
              return true;
          }
        }
      }
    }
    if (Mul) {
      if (containsAnyName(Mul->getLHS(), C, Positives) ||
          containsAnyName(Mul->getRHS(), C, Positives))
        return true;
    }
    return false;
  }

  bool looksLikeNonSizeEncodingContext(const Stmt *UseSiteStmt,
                                       const Decl *UseSiteDecl,
                                       CheckerContext &C) const {
    static const std::initializer_list<StringRef> Negatives = {
        "irq", "hwirq", "interrupt", "index", "idx", "id",
        "ino", "inode", "perm", "class", "sid"
    };
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt)) {
      if (BO->isAssignmentOp() && BO->getLHS()) {
        if (containsAnyName(BO->getLHS(), C, Negatives))
          return true;
      }
    }
    if (const auto *VD = dyn_cast_or_null<VarDecl>(UseSiteDecl)) {
      if (containsAnyNameInString(VD->getName(), Negatives))
        return true;
    }
    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(UseSiteStmt)) {
      if (const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl())) {
        if (containsAnyNameInString(FD->getName(), Negatives))
          return true;
      }
    }
    if (const auto *Call = dyn_cast_or_null<CallExpr>(UseSiteStmt)) {
      if (const FunctionDecl *FD = Call->getDirectCallee()) {
        if (containsAnyNameInString(FD->getName(), Negatives))
          return true;
        for (const ParmVarDecl *P : FD->parameters()) {
          if (containsAnyNameInString(P->getName(), Negatives))
            return true;
        }
      }
    }
    return false;
  }

  // Heuristic: detect Linux sysfs bin_attribute.size assignment patterns.
  bool isLinuxBinAttributeSizeAssignment(const Stmt *UseSiteStmt,
                                         CheckerContext &C) const {
    const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt);
    if (!BO || !BO->isAssignmentOp())
      return false;

    const Expr *LHS = BO->getLHS();
    if (!LHS)
      return false;

    LHS = LHS->IgnoreParenImpCasts();
    if (!isSizeT(LHS->getType(), C))
      return false;

    const auto *ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      return false;

    const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD)
      return false;

    if (!FD->getIdentifier() || FD->getName() != "size")
      return false;

    const RecordDecl *RD = FD->getParent();
    StringRef RName;
    if (RD) {
      if (const IdentifierInfo *II = RD->getIdentifier())
        RName = II->getName();
    }
    if (RName.empty())
      RName = getRecordNameFromExprBase(ME->getBase());

    if (RName.contains("bin_attribute") || RName.contains("attribute"))
      return true;

    return false;
  }

  // Heuristic: whether expression references an "ops" struct member (common in Linux).
  bool exprComesFromOps(const Expr *E) const {
    if (!E) return false;
    E = E->IgnoreParenImpCasts();
    const auto *ME = dyn_cast<MemberExpr>(E);
    if (!ME)
      return false;

    const Expr *Base = ME->getBase();
    StringRef BaseVarName = getDeclRefName(Base);
    StringRef RecName = getRecordNameFromExprBase(Base);
    if (BaseVarName.contains("ops") || RecName.contains("ops"))
      return true;

    return false;
  }

  // Additional FP filter: assignment to size_t and operands look like small block-based sizes.
  bool isLikelySmallBlockComputation(const BinaryOperator *Mul,
                                     const Stmt *UseSiteStmt,
                                     CheckerContext &C) const {
    const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt);
    if (!BO || !BO->isAssignmentOp())
      return false;

    const Expr *LHS = BO->getLHS();
    if (!LHS)
      return false;

    if (!isSizeT(LHS->getType(), C))
      return false;

    static const std::initializer_list<StringRef> Blocky = {
        "block", "blocks", "blk", "sector", "page", "pages"
    };
    const Expr *ML = Mul ? Mul->getLHS() : nullptr;
    const Expr *MR = Mul ? Mul->getRHS() : nullptr;
    if (!ML || !MR)
      return false;

    if (exprComesFromOps(ML) || exprComesFromOps(MR))
      return true;

    if (containsAnyName(ML, C, Blocky) || containsAnyName(MR, C, Blocky))
      return true;

    return false;
  }

  // Targeted FP filter for MSI-X mapping size: ioremap(phys_addr, nr_entries * PCI_MSIX_ENTRY_SIZE)
  bool isBenignMsixIoremapSize(const BinaryOperator *Mul,
                               const Stmt *UseSiteStmt,
                               CheckerContext &C) const {
    if (!Mul || !UseSiteStmt)
      return false;

    const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!FD)
      return false;

    // Must be in msix_map_region
    if (!FD->getIdentifier() || FD->getName() != "msix_map_region")
      return false;

    // Use site must be a call to ioremap*
    const auto *Call = dyn_cast<CallExpr>(UseSiteStmt);
    if (!Call)
      return false;
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier())
      return false;
    StringRef CalleeName = Callee->getName();
    if (!CalleeName.contains("ioremap"))
      return false;

    // The multiply must be the size argument of the call (commonly arg1).
    bool IsArgMatch = false;
    for (unsigned i = 0, n = Call->getNumArgs(); i < n; ++i) {
      if (Call->getArg(i)->IgnoreParenImpCasts() == cast<Expr>(Mul)->IgnoreParenImpCasts()) {
        IsArgMatch = true;
        break;
      }
    }
    if (!IsArgMatch)
      return false;

    // One operand must be PCI_MSIX_ENTRY_SIZE (constant 16)
    auto IsEntrySizeConst = [&](const Expr *E) -> bool {
      if (!E) return false;
      llvm::APSInt CI;
      if (EvaluateExprToInt(CI, E, C)) {
        // Be conservative: accept 16 explicitly.
        if (CI.isUnsigned() ? CI.getZExtValue() == 16
                            : (CI.getExtValue() >= 0 && (uint64_t)CI.getExtValue() == 16))
          return true;
      }
      return ExprHasName(E, "PCI_MSIX_ENTRY_SIZE", C);
    };

    // The other operand should be the parameter 'nr_entries' or a similar bounded name.
    auto IsNrEntriesParam = [&](const Expr *E) -> bool {
      if (!E) return false;
      E = E->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        if (const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
          if (PVD->getIdentifier()) {
            StringRef N = PVD->getName();
            if (N.equals("nr_entries"))
              return true;
            // Be conservative; only accept 'nr_entries' here.
          }
        }
      }
      return false;
    };

    const Expr *L = Mul->getLHS()->IgnoreParenImpCasts();
    const Expr *R = Mul->getRHS()->IgnoreParenImpCasts();

    if ((IsEntrySizeConst(L) && IsNrEntriesParam(R)) ||
        (IsEntrySizeConst(R) && IsNrEntriesParam(L)))
      return true;

    return false;
  }

  bool isFalsePositive(const BinaryOperator *Mul,
                       const Stmt *UseSiteStmt,
                       const Decl *UseSiteDecl,
                       CheckerContext &C) const {
    // Targeted suppression: MSI-X ioremap table size computation.
    if (isBenignMsixIoremapSize(Mul, UseSiteStmt, C))
      return true;

    // Targeted suppression 1: Linux sysfs bin_attribute.size patterns.
    if (isLinuxBinAttributeSizeAssignment(UseSiteStmt, C))
      return true;

    // Targeted suppression 2: size_t destination and "ops"/block-style operands.
    if (isLikelySmallBlockComputation(Mul, UseSiteStmt, C))
      return true;

    // If it doesn't look like a size/count computation, suppress.
    if (!looksLikeSizeContext(UseSiteStmt, UseSiteDecl, Mul, C))
      return true;

    // Or if it explicitly looks like a non-size encoding context, suppress.
    if (looksLikeNonSizeEncodingContext(UseSiteStmt, UseSiteDecl, C))
      return true;

    return false;
  }
};

void SAGenTestChecker::checkPostStmt(const BinaryOperator *B, CheckerContext &C) const {
  if (!B)
    return;

  // Only care about integer multiplication.
  if (B->getOpcode() != BO_Mul)
    return;
  if (!B->getType()->isIntegerType())
    return;

  // Require both operands to be integer-typed.
  if (!isIntegerType(B->getLHS()) || !isIntegerType(B->getRHS()))
    return;

  // The multiply's arithmetic width (after integer promotions).
  unsigned MulWidth = getIntWidth(B->getType(), C);

  // If arithmetic is already 64-bit or more, that's OK.
  if (MulWidth >= 64)
    return;

  // Is the multiply directly used in a 64-bit integer context?
  const Expr *E = dyn_cast<Expr>(B);
  if (!E)
    return;

  const Stmt *UseSiteStmt = nullptr;
  const Decl *UseSiteDecl = nullptr;
  if (!isDirectWidenedUseTo64(E, C, UseSiteStmt, UseSiteDecl))
    return;

  // If we can prove the product fits in the narrow arithmetic width, suppress.
  if (productDefinitelyFits(B, C))
    return;

  // Semantic filter and targeted FP filters.
  if (isFalsePositive(B, UseSiteStmt, UseSiteDecl, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply",
      N);
  R->addRange(B->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->getType()->isIntegerType())
      continue;
    if (!VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    llvm::APSInt V;
    if (EvaluateExprToInt(V, Init, C)) {
      State = State->set<ConstIntVarMap>(VD, V);
    } else {
      // If not a constant init, drop any previous knowledge.
      State = State->remove<ConstIntVarMap>(VD);
    }
  }
  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) {
    return;
  }

  const auto *VR = dyn_cast<VarRegion>(MR->getBaseRegion());
  if (!VR) {
    return;
  }

  const VarDecl *VD = VR->getDecl();
  if (!VD || !VD->getType()->isIntegerType())
    return;

  if (auto CI = Val.getAs<nonloc::ConcreteInt>()) {
    // Track constant value.
    State = State->set<ConstIntVarMap>(VD, CI->getValue());
  } else {
    // Unknown/non-constant write: drop info.
    State = State->remove<ConstIntVarMap>(VD);
  }

  if (State != C.getState())
    C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Invalidated,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
    const CallEvent *Call) const {

  for (const MemRegion *R : Regions) {
    const MemRegion *Base = R ? R->getBaseRegion() : nullptr;
    const auto *VR = dyn_cast_or_null<VarRegion>(Base);
    if (!VR)
      continue;
    const VarDecl *VD = VR->getDecl();
    if (!VD)
      continue;
    State = State->remove<ConstIntVarMap>(VD);
  }
  return State;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect 32-bit multiply whose result is only widened to 64-bit afterward, risking overflow",
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
