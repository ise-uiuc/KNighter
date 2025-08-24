# Instruction

Determine whether the static analyzer report is a real bug in the Linux kernel and matches the target bug pattern

Your analysis should:
- **Compare the report against the provided target bug pattern specification,** using the **buggy function (pre-patch)** and the **fix patch** as the reference.
- Explain your reasoning for classifying this as either:
  - **A true positive** (matches the target bug pattern **and** is a real bug), or
  - **A false positive** (does **not** match the target bug pattern **or** is **not** a real bug).

Please evaluate thoroughly using the following process:

- **First, understand** the reported code pattern and its control/data flow.
- **Then, compare** it against the target bug pattern characteristics.
- **Finally, validate** against the **pre-/post-patch** behavior:
  - The reported case demonstrates the same root cause pattern as the target bug pattern/function and would be addressed by a similar fix.

- **Numeric / bounds feasibility** (if applicable):
  - Infer tight **min/max** ranges for all involved variables from types, prior checks, and loop bounds.
  - Show whether overflow/underflow or OOB is actually triggerable (compute the smallest/largest values that violate constraints).

- **Null-pointer dereference feasibility** (if applicable):
  1. **Identify the pointer source** and return convention of the producing function(s) in this path (e.g., returns **NULL**, **ERR_PTR**, negative error code via cast, or never-null).
  2. **Check real-world feasibility in this specific driver/socket/filesystem/etc.**:
     - Enumerate concrete conditions under which the producer can return **NULL/ERR_PTR** here (e.g., missing DT/ACPI property, absent PCI device/function, probe ordering, hotplug/race, Kconfig options, chip revision/quirks).
     - Verify whether those conditions can occur given the driver’s init/probe sequence and the kernel helpers used.
  3. **Lifetime & concurrency**: consider teardown paths, RCU usage, refcounting (`get/put`), and whether the pointer can become invalid/NULL across yields or callbacks.
  4. If the producer is provably non-NULL in this context (by spec or preceding checks), classify as **false positive**.

If there is any uncertainty in the classification, **err on the side of caution and classify it as a false positive**. Your analysis will be used to improve the static analyzer's accuracy.

## Bug Pattern

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

## Bug Pattern

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

# Report

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

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
