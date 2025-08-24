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

Left-shifting a 32-bit expression and only widening to 64-bit after the shift, causing the shift to be performed in 32-bit width and overflow/truncation before assignment:

u64 tau4 = ((1 << x_w) | x) << y;   // shift happens in 32-bit -> overflow
// Correct:
u64 tau4 = (u64)((1 << x_w) | x) << y;

Root cause: the shift is evaluated in the type of the left operand (u32), so bits are lost when y or the result exceeds 32 bits; casting must occur before the shift.

## Bug Pattern

Left-shifting a 32-bit expression and only widening to 64-bit after the shift, causing the shift to be performed in 32-bit width and overflow/truncation before assignment:

u64 tau4 = ((1 << x_w) | x) << y;   // shift happens in 32-bit -> overflow
// Correct:
u64 tau4 = (u64)((1 << x_w) | x) << y;

Root cause: the shift is evaluated in the type of the left operand (u32), so bits are lost when y or the result exceeds 32 bits; casting must occur before the shift.

# Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/kernel/dma/pool.c
---|---
Warning:| line 91, column 13
Shift done in 32-bit, widened after; cast left operand to 64-bit before <<

### Annotated Source Code


29    | static int __init early_coherent_pool(char *p)
30    | {
31    | 	atomic_pool_size = memparse(p, &p);
32    |  return 0;
33    | }
34    | early_param("coherent_pool", early_coherent_pool);
35    |
36    | static void __init dma_atomic_pool_debugfs_init(void)
37    | {
38    |  struct dentry *root;
39    |
40    | 	root = debugfs_create_dir("dma_pools", NULL);
41    | 	debugfs_create_ulong("pool_size_dma", 0400, root, &pool_size_dma);
42    | 	debugfs_create_ulong("pool_size_dma32", 0400, root, &pool_size_dma32);
43    | 	debugfs_create_ulong("pool_size_kernel", 0400, root, &pool_size_kernel);
44    | }
45    |
46    | static void dma_atomic_pool_size_add(gfp_t gfp, size_t size)
47    | {
48    |  if (gfp & __GFP_DMA)
49    | 		pool_size_dma += size;
50    |  else if (gfp & __GFP_DMA32)
51    | 		pool_size_dma32 += size;
52    |  else
53    | 		pool_size_kernel += size;
54    | }
55    |
56    | static bool cma_in_zone(gfp_t gfp)
57    | {
58    |  unsigned long size;
59    | 	phys_addr_t end;
60    |  struct cma *cma;
61    |
62    | 	cma = dev_get_cma_area(NULL);
63    |  if (!cma)
64    |  return false;
65    |
66    | 	size = cma_get_size(cma);
67    |  if (!size)
68    |  return false;
69    |
70    |  /* CMA can't cross zone boundaries, see cma_activate_area() */
71    | 	end = cma_get_base(cma) + size - 1;
72    |  if (IS_ENABLED(CONFIG_ZONE_DMA) && (gfp & GFP_DMA))
73    |  return end <= DMA_BIT_MASK(zone_dma_bits);
74    |  if (IS_ENABLED(CONFIG_ZONE_DMA32) && (gfp & GFP_DMA32))
75    |  return end <= DMA_BIT_MASK(32);
76    |  return true;
77    | }
78    |
79    | static int atomic_pool_expand(struct gen_pool *pool, size_t pool_size,
80    | 			      gfp_t gfp)
81    | {
82    |  unsigned int order;
83    |  struct page *page = NULL;
84    |  void *addr;
85    |  int ret = -ENOMEM;
86    |
87    |  /* Cannot allocate larger than MAX_PAGE_ORDER */
88    |  order = min(get_order(pool_size), MAX_PAGE_ORDER);
    9←Assuming '__UNIQUE_ID___x1046' is >= '__UNIQUE_ID___y1047'→
    10←'?' condition is false→
89    |
90    |  do {
91    |  pool_size = 1 << (PAGE_SHIFT + order);
    11←Shift done in 32-bit, widened after; cast left operand to 64-bit before <<
92    |  if (cma_in_zone(gfp))
93    | 			page = dma_alloc_from_contiguous(NULL, 1 << order,
94    | 							 order, false);
95    |  if (!page)
96    | 			page = alloc_pages(gfp, order);
97    | 	} while (!page && order-- > 0);
98    |  if (!page)
99    |  goto out;
100   |
101   | 	arch_dma_prep_coherent(page, pool_size);
102   |
103   | #ifdef CONFIG_DMA_DIRECT_REMAP
104   | 	addr = dma_common_contiguous_remap(page, pool_size,
105   |  pgprot_dmacoherent(PAGE_KERNEL),
106   | 					   __builtin_return_address(0));
107   |  if (!addr)
108   |  goto free_page;
109   | #else
110   | 	addr = page_to_virt(page);
111   | #endif
112   |  /*
113   |  * Memory in the atomic DMA pools must be unencrypted, the pools do not
114   |  * shrink so no re-encryption occurs in dma_direct_free().
115   |  */
116   | 	ret = set_memory_decrypted((unsigned long)page_to_virt(page),
117   | 				   1 << order);
118   |  if (ret)
119   |  goto remove_mapping;
120   | 	ret = gen_pool_add_virt(pool, (unsigned long)addr, page_to_phys(page),
121   | 				pool_size, NUMA_NO_NODE);
122   |  if (ret)
123   |  goto encrypt_mapping;
124   |
125   | 	dma_atomic_pool_size_add(gfp, pool_size);
126   |  return 0;
127   |
128   | encrypt_mapping:
129   | 	ret = set_memory_encrypted((unsigned long)page_to_virt(page),
130   | 				   1 << order);
131   |  if (WARN_ON_ONCE(ret)) {
132   |  /* Decrypt succeeded but encrypt failed, purposely leak */
133   |  goto out;
134   | 	}
135   | remove_mapping:
136   | #ifdef CONFIG_DMA_DIRECT_REMAP
137   | 	dma_common_free_remap(addr, pool_size);
138   | free_page:
139   | 	__free_pages(page, order);
140   | #endif
141   | out:
142   |  return ret;
143   | }
144   |
145   | static void atomic_pool_resize(struct gen_pool *pool, gfp_t gfp)
146   | {
147   |  if (pool && gen_pool_avail(pool) < atomic_pool_size)
148   | 		atomic_pool_expand(pool, gen_pool_size(pool), gfp);
149   | }
150   |
151   | static void atomic_pool_work_fn(struct work_struct *work)
152   | {
153   |  if (IS_ENABLED(CONFIG_ZONE_DMA))
154   | 		atomic_pool_resize(atomic_pool_dma,
155   |  GFP_KERNEL | GFP_DMA);
156   |  if (IS_ENABLED(CONFIG_ZONE_DMA32))
157   | 		atomic_pool_resize(atomic_pool_dma32,
158   |  GFP_KERNEL | GFP_DMA32);
159   | 	atomic_pool_resize(atomic_pool_kernel, GFP_KERNEL);
160   | }
161   |
162   | static __init struct gen_pool *__dma_atomic_pool_init(size_t pool_size,
163   | 						      gfp_t gfp)
164   | {
165   |  struct gen_pool *pool;
166   |  int ret;
167   |
168   | 	pool = gen_pool_create(PAGE_SHIFT, NUMA_NO_NODE);
169   |  if (!pool)
    6←Assuming 'pool' is non-null→
    7←Taking false branch→
170   |  return NULL;
171   |
172   |  gen_pool_set_algo(pool, gen_pool_first_fit_order_align, NULL);
173   |
174   |  ret = atomic_pool_expand(pool, pool_size, gfp);
    8←Calling 'atomic_pool_expand'→
175   |  if (ret) {
176   | 		gen_pool_destroy(pool);
177   |  pr_err("DMA: failed to allocate %zu KiB %pGg pool for atomic allocation\n",
178   |  pool_size >> 10, &gfp);
179   |  return NULL;
180   | 	}
181   |
182   |  pr_info("DMA: preallocated %zu KiB %pGg pool for atomic allocations\n",
183   |  gen_pool_size(pool) >> 10, &gfp);
184   |  return pool;
185   | }
186   |
187   | static int __init dma_atomic_pool_init(void)
188   | {
189   |  int ret = 0;
190   |
191   |  /*
192   |  * If coherent_pool was not used on the command line, default the pool
193   |  * sizes to 128KB per 1GB of memory, min 128KB, max MAX_PAGE_ORDER.
194   |  */
195   |  if (!atomic_pool_size) {
    1Assuming 'atomic_pool_size' is not equal to 0→
    2←Taking false branch→
196   |  unsigned long pages = totalram_pages() / (SZ_1G / SZ_128K);
197   | 		pages = min_t(unsigned long, pages, MAX_ORDER_NR_PAGES);
198   | 		atomic_pool_size = max_t(size_t, pages << PAGE_SHIFT, SZ_128K);
199   | 	}
200   |  INIT_WORK(&atomic_pool_work, atomic_pool_work_fn);
    3←Loop condition is false.  Exiting loop→
    4←Loop condition is false.  Exiting loop→
201   |
202   |  atomic_pool_kernel = __dma_atomic_pool_init(atomic_pool_size,
    5←Calling '__dma_atomic_pool_init'→
203   |  GFP_KERNEL);
204   |  if (!atomic_pool_kernel)
205   | 		ret = -ENOMEM;
206   |  if (has_managed_dma()) {
207   | 		atomic_pool_dma = __dma_atomic_pool_init(atomic_pool_size,
208   |  GFP_KERNEL | GFP_DMA);
209   |  if (!atomic_pool_dma)
210   | 			ret = -ENOMEM;
211   | 	}
212   |  if (IS_ENABLED(CONFIG_ZONE_DMA32)) {
213   | 		atomic_pool_dma32 = __dma_atomic_pool_init(atomic_pool_size,
214   |  GFP_KERNEL | GFP_DMA32);
215   |  if (!atomic_pool_dma32)
216   | 			ret = -ENOMEM;
217   | 	}
218   |
219   | 	dma_atomic_pool_debugfs_init();
220   |  return ret;
221   | }
222   | postcore_initcall(dma_atomic_pool_init);
223   |
224   | static inline struct gen_pool *dma_guess_pool(struct gen_pool *prev, gfp_t gfp)
225   | {
226   |  if (prev == NULL) {
227   |  if (IS_ENABLED(CONFIG_ZONE_DMA32) && (gfp & GFP_DMA32))
228   |  return atomic_pool_dma32;
229   |  if (atomic_pool_dma && (gfp & GFP_DMA))
230   |  return atomic_pool_dma;
231   |  return atomic_pool_kernel;
232   | 	}
233   |  if (prev == atomic_pool_kernel)

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
