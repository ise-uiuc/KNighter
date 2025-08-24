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

File:| drivers/md/dm-log-writes.c
---|---
Warning:| line 391, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


94    |  * entry stuff, the MARK data provided by userspace for example.
95    |  */
96    | struct log_write_entry {
97    | 	__le64 sector;
98    | 	__le64 nr_sectors;
99    | 	__le64 flags;
100   | 	__le64 data_len;
101   | };
102   |
103   | struct log_writes_c {
104   |  struct dm_dev *dev;
105   |  struct dm_dev *logdev;
106   | 	u64 logged_entries;
107   | 	u32 sectorsize;
108   | 	u32 sectorshift;
109   | 	atomic_t io_blocks;
110   | 	atomic_t pending_blocks;
111   | 	sector_t next_sector;
112   | 	sector_t end_sector;
113   | 	bool logging_enabled;
114   | 	bool device_supports_discard;
115   | 	spinlock_t blocks_lock;
116   |  struct list_head unflushed_blocks;
117   |  struct list_head logging_blocks;
118   | 	wait_queue_head_t wait;
119   |  struct task_struct *log_kthread;
120   |  struct completion super_done;
121   | };
122   |
123   | struct pending_block {
124   |  int vec_cnt;
125   | 	u64 flags;
126   | 	sector_t sector;
127   | 	sector_t nr_sectors;
128   |  char *data;
129   | 	u32 datalen;
130   |  struct list_head list;
131   |  struct bio_vec vecs[];
132   | };
133   |
134   | struct per_bio_data {
135   |  struct pending_block *block;
136   | };
137   |
138   | static inline sector_t bio_to_dev_sectors(struct log_writes_c *lc,
139   | 					  sector_t sectors)
140   | {
141   |  return sectors >> (lc->sectorshift - SECTOR_SHIFT);
142   | }
143   |
144   | static inline sector_t dev_to_bio_sectors(struct log_writes_c *lc,
145   | 					  sector_t sectors)
146   | {
147   |  return sectors << (lc->sectorshift - SECTOR_SHIFT);
148   | }
149   |
150   | static void put_pending_block(struct log_writes_c *lc)
151   | {
152   |  if (atomic_dec_and_test(&lc->pending_blocks)) {
153   |  smp_mb__after_atomic();
154   |  if (waitqueue_active(&lc->wait))
155   |  wake_up(&lc->wait);
156   | 	}
157   | }
158   |
159   | static void put_io_block(struct log_writes_c *lc)
160   | {
161   |  if (atomic_dec_and_test(&lc->io_blocks)) {
162   |  smp_mb__after_atomic();
163   |  if (waitqueue_active(&lc->wait))
164   |  wake_up(&lc->wait);
165   | 	}
166   | }
167   |
168   | static void log_end_io(struct bio *bio)
169   | {
170   |  struct log_writes_c *lc = bio->bi_private;
171   |
172   |  if (bio->bi_status) {
173   |  unsigned long flags;
174   |
175   |  DMERR("Error writing log block, error=%d", bio->bi_status);
176   |  spin_lock_irqsave(&lc->blocks_lock, flags);
177   | 		lc->logging_enabled = false;
178   | 		spin_unlock_irqrestore(&lc->blocks_lock, flags);
179   | 	}
180   |
181   | 	bio_free_pages(bio);
182   | 	put_io_block(lc);
183   | 	bio_put(bio);
184   | }
185   |
186   | static void log_end_super(struct bio *bio)
187   | {
188   |  struct log_writes_c *lc = bio->bi_private;
189   |
190   | 	complete(&lc->super_done);
191   | 	log_end_io(bio);
192   | }
193   |
194   | /*
195   |  * Meant to be called if there is an error, it will free all the pages
196   |  * associated with the block.
197   |  */
198   | static void free_pending_block(struct log_writes_c *lc,
199   |  struct pending_block *block)
200   | {
201   |  int i;
202   |
203   |  for (i = 0; i < block->vec_cnt; i++) {
204   |  if (block->vecs[i].bv_page)
205   |  __free_page(block->vecs[i].bv_page);
206   | 	}
207   | 	kfree(block->data);
208   | 	kfree(block);
209   | 	put_pending_block(lc);
210   | }
211   |
212   | static int write_metadata(struct log_writes_c *lc, void *entry,
213   | 			  size_t entrylen, void *data, size_t datalen,
214   | 			  sector_t sector)
215   | {
216   |  struct bio *bio;
217   |  struct page *page;
218   |  void *ptr;
219   | 	size_t ret;
220   |
221   | 	bio = bio_alloc(lc->logdev->bdev, 1, REQ_OP_WRITE, GFP_KERNEL);
222   | 	bio->bi_iter.bi_size = 0;
223   | 	bio->bi_iter.bi_sector = sector;
224   | 	bio->bi_end_io = (sector == WRITE_LOG_SUPER_SECTOR) ?
225   | 			  log_end_super : log_end_io;
226   | 	bio->bi_private = lc;
227   |
228   | 	page = alloc_page(GFP_KERNEL);
229   |  if (!page) {
230   |  DMERR("Couldn't alloc log page");
231   | 		bio_put(bio);
232   |  goto error;
233   | 	}
234   |
235   | 	ptr = kmap_local_page(page);
236   |  memcpy(ptr, entry, entrylen);
237   |  if (datalen)
238   |  memcpy(ptr + entrylen, data, datalen);
239   |  memset(ptr + entrylen + datalen, 0,
240   |  lc->sectorsize - entrylen - datalen);
241   |  kunmap_local(ptr);
242   |
243   | 	ret = bio_add_page(bio, page, lc->sectorsize, 0);
244   |  if (ret != lc->sectorsize) {
245   |  DMERR("Couldn't add page to the log block");
246   |  goto error_bio;
247   | 	}
248   | 	submit_bio(bio);
249   |  return 0;
250   | error_bio:
251   | 	bio_put(bio);
252   |  __free_page(page);
253   | error:
254   | 	put_io_block(lc);
255   |  return -1;
256   | }
257   |
258   | static int write_inline_data(struct log_writes_c *lc, void *entry,
259   | 			     size_t entrylen, void *data, size_t datalen,
260   | 			     sector_t sector)
261   | {
262   |  int bio_pages, pg_datalen, pg_sectorlen, i;
263   |  struct page *page;
264   |  struct bio *bio;
265   | 	size_t ret;
266   |  void *ptr;
267   |
268   |  while (datalen) {
269   | 		bio_pages = bio_max_segs(DIV_ROUND_UP(datalen, PAGE_SIZE));
270   |
271   | 		atomic_inc(&lc->io_blocks);
272   |
273   | 		bio = bio_alloc(lc->logdev->bdev, bio_pages, REQ_OP_WRITE,
274   |  GFP_KERNEL);
275   | 		bio->bi_iter.bi_size = 0;
276   | 		bio->bi_iter.bi_sector = sector;
277   | 		bio->bi_end_io = log_end_io;
278   | 		bio->bi_private = lc;
279   |
280   |  for (i = 0; i < bio_pages; i++) {
281   | 			pg_datalen = min_t(int, datalen, PAGE_SIZE);
282   | 			pg_sectorlen = ALIGN(pg_datalen, lc->sectorsize);
283   |
284   | 			page = alloc_page(GFP_KERNEL);
285   |  if (!page) {
286   |  DMERR("Couldn't alloc inline data page");
287   |  goto error_bio;
288   | 			}
289   |
290   | 			ptr = kmap_local_page(page);
291   |  memcpy(ptr, data, pg_datalen);
292   |  if (pg_sectorlen > pg_datalen)
293   |  memset(ptr + pg_datalen, 0, pg_sectorlen - pg_datalen);
294   |  kunmap_local(ptr);
295   |
296   | 			ret = bio_add_page(bio, page, pg_sectorlen, 0);
297   |  if (ret != pg_sectorlen) {
298   |  DMERR("Couldn't add page of inline data");
299   |  __free_page(page);
300   |  goto error_bio;
301   | 			}
302   |
303   | 			datalen -= pg_datalen;
304   | 			data	+= pg_datalen;
305   | 		}
306   | 		submit_bio(bio);
307   |
308   | 		sector += bio_pages * PAGE_SECTORS;
309   | 	}
310   |  return 0;
311   | error_bio:
312   | 	bio_free_pages(bio);
313   | 	bio_put(bio);
314   | 	put_io_block(lc);
315   |  return -1;
316   | }
317   |
318   | static int log_one_block(struct log_writes_c *lc,
319   |  struct pending_block *block, sector_t sector)
320   | {
321   |  struct bio *bio;
322   |  struct log_write_entry entry;
323   | 	size_t metadatalen, ret;
324   |  int i;
325   |
326   | 	entry.sector = cpu_to_le64(block->sector);
327   | 	entry.nr_sectors = cpu_to_le64(block->nr_sectors);
328   | 	entry.flags = cpu_to_le64(block->flags);
329   | 	entry.data_len = cpu_to_le64(block->datalen);
330   |
331   |  metadatalen = (block->flags & LOG_MARK_FLAG) ? block->datalen : 0;
    17←Assuming the condition is true→
    18←'?' condition is true→
332   |  if (write_metadata(lc, &entry, sizeof(entry), block->data,
    19←Taking false branch→
333   | 			   metadatalen, sector)) {
334   | 		free_pending_block(lc, block);
335   |  return -1;
336   | 	}
337   |
338   |  sector += dev_to_bio_sectors(lc, 1);
339   |
340   |  if (block->datalen19.1Field 'datalen' is 0 && metadatalen == 0) {
341   |  if (write_inline_data(lc, &entry, sizeof(entry), block->data,
342   | 				      block->datalen, sector)) {
343   | 			free_pending_block(lc, block);
344   |  return -1;
345   | 		}
346   |  /* we don't support both inline data & bio data */
347   |  goto out;
348   | 	}
349   |
350   |  if (!block->vec_cnt)
    20←Assuming field 'vec_cnt' is 0→
    21←Taking true branch→
351   |  goto out;
    22←Control jumps to line 391→
352   |
353   | 	atomic_inc(&lc->io_blocks);
354   | 	bio = bio_alloc(lc->logdev->bdev, bio_max_segs(block->vec_cnt),
355   | 			REQ_OP_WRITE, GFP_KERNEL);
356   | 	bio->bi_iter.bi_size = 0;
357   | 	bio->bi_iter.bi_sector = sector;
358   | 	bio->bi_end_io = log_end_io;
359   | 	bio->bi_private = lc;
360   |
361   |  for (i = 0; i < block->vec_cnt; i++) {
362   |  /*
363   |  * The page offset is always 0 because we allocate a new page
364   |  * for every bvec in the original bio for simplicity sake.
365   |  */
366   | 		ret = bio_add_page(bio, block->vecs[i].bv_page,
367   | 				   block->vecs[i].bv_len, 0);
368   |  if (ret != block->vecs[i].bv_len) {
369   | 			atomic_inc(&lc->io_blocks);
370   | 			submit_bio(bio);
371   | 			bio = bio_alloc(lc->logdev->bdev,
372   | 					bio_max_segs(block->vec_cnt - i),
373   | 					REQ_OP_WRITE, GFP_KERNEL);
374   | 			bio->bi_iter.bi_size = 0;
375   | 			bio->bi_iter.bi_sector = sector;
376   | 			bio->bi_end_io = log_end_io;
377   | 			bio->bi_private = lc;
378   |
379   | 			ret = bio_add_page(bio, block->vecs[i].bv_page,
380   | 					   block->vecs[i].bv_len, 0);
381   |  if (ret != block->vecs[i].bv_len) {
382   |  DMERR("Couldn't add page on new bio?");
383   | 				bio_put(bio);
384   |  goto error;
385   | 			}
386   | 		}
387   | 		sector += block->vecs[i].bv_len >> SECTOR_SHIFT;
388   | 	}
389   | 	submit_bio(bio);
390   | out:
391   |  kfree(block->data);
    23←Freeing unowned field in shared error label; possible double free
392   | 	kfree(block);
393   | 	put_pending_block(lc);
394   |  return 0;
395   | error:
396   | 	free_pending_block(lc, block);
397   | 	put_io_block(lc);
398   |  return -1;
399   | }
400   |
401   | static int log_super(struct log_writes_c *lc)
402   | {
403   |  struct log_write_super super;
404   |
405   | 	super.magic = cpu_to_le64(WRITE_LOG_MAGIC);
406   | 	super.version = cpu_to_le64(WRITE_LOG_VERSION);
407   | 	super.nr_entries = cpu_to_le64(lc->logged_entries);
408   | 	super.sectorsize = cpu_to_le32(lc->sectorsize);
409   |
410   |  if (write_metadata(lc, &super, sizeof(super), NULL, 0,
411   |  WRITE_LOG_SUPER_SECTOR)) {
412   |  DMERR("Couldn't write super");
413   |  return -1;
414   | 	}
415   |
416   |  /*
417   |  * Super sector should be writen in-order, otherwise the
418   |  * nr_entries could be rewritten incorrectly by an old bio.
419   |  */
420   | 	wait_for_completion_io(&lc->super_done);
421   |
422   |  return 0;
423   | }
424   |
425   | static inline sector_t logdev_last_sector(struct log_writes_c *lc)
426   | {
427   |  return bdev_nr_sectors(lc->logdev->bdev);
428   | }
429   |
430   | static int log_writes_kthread(void *arg)
431   | {
432   |  struct log_writes_c *lc = arg;
433   | 	sector_t sector = 0;
434   |
435   |  while (!kthread_should_stop()) {
    1Assuming the condition is true→
    2←Loop condition is true.  Entering loop body→
436   |  bool super = false;
437   | 		bool logging_enabled;
438   |  struct pending_block *block = NULL;
439   |  int ret;
440   |
441   | 		spin_lock_irq(&lc->blocks_lock);
442   |  if (!list_empty(&lc->logging_blocks)) {
    3←Assuming the condition is true→
    4←Taking true branch→
443   | 			block = list_first_entry(&lc->logging_blocks,
444   |  struct pending_block, list);
445   |  list_del_init(&block->list);
446   |  if (!lc->logging_enabled)
    5←Assuming field 'logging_enabled' is true→
    6←Taking false branch→
447   |  goto next;
448   |
449   |  sector = lc->next_sector;
450   |  if (!(block->flags & LOG_DISCARD_FLAG))
    7←Assuming the condition is false→
    8←Taking false branch→
451   | 				lc->next_sector += dev_to_bio_sectors(lc, block->nr_sectors);
452   |  lc->next_sector += dev_to_bio_sectors(lc, 1);
453   |
454   |  /*
455   |  * Apparently the size of the device may not be known
456   |  * right away, so handle this properly.
457   |  */
458   |  if (!lc->end_sector)
    9←Assuming field 'end_sector' is not equal to 0→
459   | 				lc->end_sector = logdev_last_sector(lc);
460   |  if (lc->end_sector9.1Field 'end_sector' is not equal to 0 &&
    11←Taking false branch→
461   |  lc->next_sector >= lc->end_sector) {
    10←Assuming field 'next_sector' is < field 'end_sector'→
462   |  DMERR("Ran out of space on the logdev");
463   | 				lc->logging_enabled = false;
464   |  goto next;
465   | 			}
466   |  lc->logged_entries++;
467   | 			atomic_inc(&lc->io_blocks);
468   |
469   | 			super = (block->flags & (LOG_FUA_FLAG | LOG_MARK_FLAG));
470   |  if (super)
    12←Assuming 'super' is true→
    13←Taking true branch→
471   |  atomic_inc(&lc->io_blocks);
472   | 		}
473   | next:
474   |  logging_enabled = lc->logging_enabled;
475   |  spin_unlock_irq(&lc->blocks_lock);
476   |  if (block13.1'block' is non-null) {
    14←Taking true branch→
477   |  if (logging_enabled14.1'logging_enabled' is true) {
    15←Taking true branch→
478   |  ret = log_one_block(lc, block, sector);
    16←Calling 'log_one_block'→
479   |  if (!ret && super)
480   | 					ret = log_super(lc);
481   |  if (ret) {
482   | 					spin_lock_irq(&lc->blocks_lock);
483   | 					lc->logging_enabled = false;
484   | 					spin_unlock_irq(&lc->blocks_lock);
485   | 				}
486   | 			} else
487   | 				free_pending_block(lc, block);
488   |  continue;
489   | 		}
490   |
491   |  if (!try_to_freeze()) {
492   |  set_current_state(TASK_INTERRUPTIBLE);
493   |  if (!kthread_should_stop() &&
494   | 			    list_empty(&lc->logging_blocks))
495   | 				schedule();
496   |  __set_current_state(TASK_RUNNING);
497   | 		}
498   | 	}
499   |  return 0;
500   | }
501   |
502   | /*
503   |  * Construct a log-writes mapping:
504   |  * log-writes <dev_path> <log_dev_path>
505   |  */
506   | static int log_writes_ctr(struct dm_target *ti, unsigned int argc, char **argv)
507   | {
508   |  struct log_writes_c *lc;

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
