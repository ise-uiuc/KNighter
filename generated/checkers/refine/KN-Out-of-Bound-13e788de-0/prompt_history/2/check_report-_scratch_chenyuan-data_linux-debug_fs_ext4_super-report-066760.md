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

Off-by-one index validation: using `if (idx > MAX)` instead of `if (idx >= MAX)` when checking user-provided indices against an array bound constant, where the array is sized `MAX` and valid indices are `[0..MAX-1]`. This allows `idx == MAX` to pass, and subsequent use (e.g., accessing `array[idx]` or `array[idx + 1]`) can cause out-of-bounds access.

## Bug Pattern

Off-by-one index validation: using `if (idx > MAX)` instead of `if (idx >= MAX)` when checking user-provided indices against an array bound constant, where the array is sized `MAX` and valid indices are `[0..MAX-1]`. This allows `idx == MAX` to pass, and subsequent use (e.g., accessing `array[idx]` or `array[idx + 1]`) can cause out-of-bounds access.

# Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/fs/ext4/super.c
---|---
Warning:| line 4535, column 10
Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation

### Annotated Source Code


140   | 	.fs_flags		= FS_REQUIRES_DEV,
141   | };
142   | MODULE_ALIAS_FS("ext2");
143   | MODULE_ALIAS("ext2");
144   | #define IS_EXT2_SB(sb) ((sb)->s_type == &ext2_fs_type)
145   | #else
146   | #define IS_EXT2_SB(sb) (0)
147   | #endif
148   |
149   |
150   | static struct file_system_type ext3_fs_type = {
151   | 	.owner			= THIS_MODULE,
152   | 	.name			= "ext3",
153   | 	.init_fs_context	= ext4_init_fs_context,
154   | 	.parameters		= ext4_param_specs,
155   | 	.kill_sb		= ext4_kill_sb,
156   | 	.fs_flags		= FS_REQUIRES_DEV,
157   | };
158   | MODULE_ALIAS_FS("ext3");
159   | MODULE_ALIAS("ext3");
160   | #define IS_EXT3_SB(sb) ((sb)->s_type == &ext3_fs_type)
161   |
162   |
163   | static inline void __ext4_read_bh(struct buffer_head *bh, blk_opf_t op_flags,
164   | 				  bh_end_io_t *end_io)
165   | {
166   |  /*
167   |  * buffer's verified bit is no longer valid after reading from
168   |  * disk again due to write out error, clear it to make sure we
169   |  * recheck the buffer contents.
170   |  */
171   | 	clear_buffer_verified(bh);
172   |
173   | 	bh->b_end_io = end_io ? end_io : end_buffer_read_sync;
174   | 	get_bh(bh);
175   | 	submit_bh(REQ_OP_READ | op_flags, bh);
176   | }
177   |
178   | void ext4_read_bh_nowait(struct buffer_head *bh, blk_opf_t op_flags,
179   | 			 bh_end_io_t *end_io)
180   | {
181   |  BUG_ON(!buffer_locked(bh));
182   |
183   |  if (ext4_buffer_uptodate(bh)) {
184   | 		unlock_buffer(bh);
185   |  return;
186   | 	}
187   | 	__ext4_read_bh(bh, op_flags, end_io);
188   | }
189   |
190   | int ext4_read_bh(struct buffer_head *bh, blk_opf_t op_flags, bh_end_io_t *end_io)
191   | {
192   |  BUG_ON(!buffer_locked(bh));
193   |
194   |  if (ext4_buffer_uptodate(bh)) {
195   | 		unlock_buffer(bh);
196   |  return 0;
197   | 	}
198   |
199   | 	__ext4_read_bh(bh, op_flags, end_io);
200   |
201   | 	wait_on_buffer(bh);
202   |  if (buffer_uptodate(bh))
203   |  return 0;
204   |  return -EIO;
205   | }
206   |
207   | int ext4_read_bh_lock(struct buffer_head *bh, blk_opf_t op_flags, bool wait)
208   | {
209   | 	lock_buffer(bh);
210   |  if (!wait) {
211   | 		ext4_read_bh_nowait(bh, op_flags, NULL);
212   |  return 0;
213   | 	}
214   |  return ext4_read_bh(bh, op_flags, NULL);
215   | }
216   |
217   | /*
218   |  * This works like __bread_gfp() except it uses ERR_PTR for error
219   |  * returns.  Currently with sb_bread it's impossible to distinguish
220   |  * between ENOMEM and EIO situations (since both result in a NULL
221   |  * return.
222   |  */
223   | static struct buffer_head *__ext4_sb_bread_gfp(struct super_block *sb,
224   | 					       sector_t block,
225   | 					       blk_opf_t op_flags, gfp_t gfp)
226   | {
227   |  struct buffer_head *bh;
228   |  int ret;
229   |
230   | 	bh = sb_getblk_gfp(sb, block, gfp);
231   |  if (bh == NULL)
232   |  return ERR_PTR(-ENOMEM);
233   |  if (ext4_buffer_uptodate(bh))
234   |  return bh;
235   |
236   | 	ret = ext4_read_bh_lock(bh, REQ_META | op_flags, true);
237   |  if (ret) {
238   | 		put_bh(bh);
239   |  return ERR_PTR(ret);
240   | 	}
241   |  return bh;
242   | }
243   |
244   | struct buffer_head *ext4_sb_bread(struct super_block *sb, sector_t block,
245   | 				   blk_opf_t op_flags)
246   | {
247   | 	gfp_t gfp = mapping_gfp_constraint(sb->s_bdev->bd_inode->i_mapping,
248   | 			~__GFP_FS) | __GFP_MOVABLE;
249   |
250   |  return __ext4_sb_bread_gfp(sb, block, op_flags, gfp);
251   | }
252   |
253   | struct buffer_head *ext4_sb_bread_unmovable(struct super_block *sb,
254   | 					    sector_t block)
255   | {
256   | 	gfp_t gfp = mapping_gfp_constraint(sb->s_bdev->bd_inode->i_mapping,
257   | 			~__GFP_FS);
258   |
259   |  return __ext4_sb_bread_gfp(sb, block, 0, gfp);
260   | }
261   |
262   | void ext4_sb_breadahead_unmovable(struct super_block *sb, sector_t block)
263   | {
264   |  struct buffer_head *bh = bdev_getblk(sb->s_bdev, block,
265   | 			sb->s_blocksize, GFP_NOWAIT | __GFP_NOWARN);
266   |
267   |  if (likely(bh)) {
268   |  if (trylock_buffer(bh))
269   | 			ext4_read_bh_nowait(bh, REQ_RAHEAD, NULL);
270   | 		brelse(bh);
271   | 	}
272   | }
273   |
274   | static int ext4_verify_csum_type(struct super_block *sb,
275   |  struct ext4_super_block *es)
276   | {
277   |  if (!ext4_has_feature_metadata_csum(sb))
278   |  return 1;
279   |
280   |  return es->s_checksum_type == EXT4_CRC32C_CHKSUM;
281   | }
282   |
283   | __le32 ext4_superblock_csum(struct super_block *sb,
284   |  struct ext4_super_block *es)
285   | {
286   |  struct ext4_sb_info *sbi = EXT4_SB(sb);
287   |  int offset = offsetof(struct ext4_super_block, s_checksum);
288   | 	__u32 csum;
289   |
290   | 	csum = ext4_chksum(sbi, ~0, (char *)es, offset);
291   |
292   |  return cpu_to_le32(csum);
293   | }
294   |
295   | static int ext4_superblock_csum_verify(struct super_block *sb,
296   |  struct ext4_super_block *es)
297   | {
298   |  if (!ext4_has_metadata_csum(sb))
299   |  return 1;
300   |
301   |  return es->s_checksum == ext4_superblock_csum(sb, es);
302   | }
303   |
304   | void ext4_superblock_csum_set(struct super_block *sb)
305   | {
306   |  struct ext4_super_block *es = EXT4_SB(sb)->s_es;
307   |
308   |  if (!ext4_has_metadata_csum(sb))
309   |  return;
310   |
311   | 	es->s_checksum = ext4_superblock_csum(sb, es);
312   | }
313   |
314   | ext4_fsblk_t ext4_block_bitmap(struct super_block *sb,
315   |  struct ext4_group_desc *bg)
316   | {
317   |  return le32_to_cpu(bg->bg_block_bitmap_lo) |
318   | 		(EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ?
319   | 		 (ext4_fsblk_t)le32_to_cpu(bg->bg_block_bitmap_hi) << 32 : 0);
320   | }
321   |
322   | ext4_fsblk_t ext4_inode_bitmap(struct super_block *sb,
323   |  struct ext4_group_desc *bg)
324   | {
325   |  return le32_to_cpu(bg->bg_inode_bitmap_lo) |
326   | 		(EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ?
327   | 		 (ext4_fsblk_t)le32_to_cpu(bg->bg_inode_bitmap_hi) << 32 : 0);
328   | }
329   |
4249  |  smp_wmb();
4250  |  free_page((unsigned long) buf);
4251  |  return 0;
4252  | }
4253  |
4254  | static void ext4_set_resv_clusters(struct super_block *sb)
4255  | {
4256  | 	ext4_fsblk_t resv_clusters;
4257  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
4258  |
4259  |  /*
4260  |  * There's no need to reserve anything when we aren't using extents.
4261  |  * The space estimates are exact, there are no unwritten extents,
4262  |  * hole punching doesn't need new metadata... This is needed especially
4263  |  * to keep ext2/3 backward compatibility.
4264  |  */
4265  |  if (!ext4_has_feature_extents(sb))
4266  |  return;
4267  |  /*
4268  |  * By default we reserve 2% or 4096 clusters, whichever is smaller.
4269  |  * This should cover the situations where we can not afford to run
4270  |  * out of space like for example punch hole, or converting
4271  |  * unwritten extents in delalloc path. In most cases such
4272  |  * allocation would require 1, or 2 blocks, higher numbers are
4273  |  * very rare.
4274  |  */
4275  | 	resv_clusters = (ext4_blocks_count(sbi->s_es) >>
4276  | 			 sbi->s_cluster_bits);
4277  |
4278  |  do_div(resv_clusters, 50);
4279  | 	resv_clusters = min_t(ext4_fsblk_t, resv_clusters, 4096);
4280  |
4281  | 	atomic64_set(&sbi->s_resv_clusters, resv_clusters);
4282  | }
4283  |
4284  | static const char *ext4_quota_mode(struct super_block *sb)
4285  | {
4286  | #ifdef CONFIG_QUOTA
4287  |  if (!ext4_quota_capable(sb))
4288  |  return "none";
4289  |
4290  |  if (EXT4_SB(sb)->s_journal && ext4_is_quota_journalled(sb))
4291  |  return "journalled";
4292  |  else
4293  |  return "writeback";
4294  | #else
4295  |  return "disabled";
4296  | #endif
4297  | }
4298  |
4299  | static void ext4_setup_csum_trigger(struct super_block *sb,
4300  |  enum ext4_journal_trigger_type type,
4301  |  void (*trigger)(
4302  |  struct jbd2_buffer_trigger_type *type,
4303  |  struct buffer_head *bh,
4304  |  void *mapped_data,
4305  | 					size_t size))
4306  | {
4307  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
4308  |
4309  | 	sbi->s_journal_triggers[type].sb = sb;
4310  | 	sbi->s_journal_triggers[type].tr_triggers.t_frozen = trigger;
4311  | }
4312  |
4313  | static void ext4_free_sbi(struct ext4_sb_info *sbi)
4314  | {
4315  |  if (!sbi)
4316  |  return;
4317  |
4318  | 	kfree(sbi->s_blockgroup_lock);
4319  | 	fs_put_dax(sbi->s_daxdev, NULL);
4320  | 	kfree(sbi);
4321  | }
4322  |
4323  | static struct ext4_sb_info *ext4_alloc_sbi(struct super_block *sb)
4324  | {
4325  |  struct ext4_sb_info *sbi;
4326  |
4327  | 	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
4328  |  if (!sbi)
4329  |  return NULL;
4330  |
4331  | 	sbi->s_daxdev = fs_dax_get_by_bdev(sb->s_bdev, &sbi->s_dax_part_off,
4332  |  NULL, NULL);
4333  |
4334  | 	sbi->s_blockgroup_lock =
4335  | 		kzalloc(sizeof(struct blockgroup_lock), GFP_KERNEL);
4336  |
4337  |  if (!sbi->s_blockgroup_lock)
4338  |  goto err_out;
4339  |
4340  | 	sb->s_fs_info = sbi;
4341  | 	sbi->s_sb = sb;
4342  |  return sbi;
4343  | err_out:
4344  | 	fs_put_dax(sbi->s_daxdev, NULL);
4345  | 	kfree(sbi);
4346  |  return NULL;
4347  | }
4348  |
4349  | static void ext4_set_def_opts(struct super_block *sb,
4350  |  struct ext4_super_block *es)
4351  | {
4352  |  unsigned long def_mount_opts;
4353  |
4354  |  /* Set defaults before we parse the mount options */
4355  | 	def_mount_opts = le32_to_cpu(es->s_default_mount_opts);
4356  |  set_opt(sb, INIT_INODE_TABLE);
4357  |  if (def_mount_opts & EXT4_DEFM_DEBUG)
4358  |  set_opt(sb, DEBUG);
4359  |  if (def_mount_opts & EXT4_DEFM_BSDGROUPS)
4360  |  set_opt(sb, GRPID);
4361  |  if (def_mount_opts & EXT4_DEFM_UID16)
4362  |  set_opt(sb, NO_UID32);
4363  |  /* xattr user namespace & acls are now defaulted on */
4364  |  set_opt(sb, XATTR_USER);
4365  | #ifdef CONFIG_EXT4_FS_POSIX_ACL
4366  |  set_opt(sb, POSIX_ACL);
4367  | #endif
4368  |  if (ext4_has_feature_fast_commit(sb))
4369  |  set_opt2(sb, JOURNAL_FAST_COMMIT);
4370  |  /* don't forget to enable journal_csum when metadata_csum is enabled. */
4371  |  if (ext4_has_metadata_csum(sb))
4372  |  set_opt(sb, JOURNAL_CHECKSUM);
4373  |
4374  |  if ((def_mount_opts & EXT4_DEFM_JMODE) == EXT4_DEFM_JMODE_DATA)
4375  |  set_opt(sb, JOURNAL_DATA);
4376  |  else if ((def_mount_opts & EXT4_DEFM_JMODE) == EXT4_DEFM_JMODE_ORDERED)
4377  |  set_opt(sb, ORDERED_DATA);
4378  |  else if ((def_mount_opts & EXT4_DEFM_JMODE) == EXT4_DEFM_JMODE_WBACK)
4379  |  set_opt(sb, WRITEBACK_DATA);
4380  |
4381  |  if (le16_to_cpu(es->s_errors) == EXT4_ERRORS_PANIC)
4382  |  set_opt(sb, ERRORS_PANIC);
4383  |  else if (le16_to_cpu(es->s_errors) == EXT4_ERRORS_CONTINUE)
4384  |  set_opt(sb, ERRORS_CONT);
4385  |  else
4386  |  set_opt(sb, ERRORS_RO);
4387  |  /* block_validity enabled by default; disable with noblock_validity */
4388  |  set_opt(sb, BLOCK_VALIDITY);
4389  |  if (def_mount_opts & EXT4_DEFM_DISCARD)
4390  |  set_opt(sb, DISCARD);
4391  |
4392  |  if ((def_mount_opts & EXT4_DEFM_NOBARRIER) == 0)
4393  |  set_opt(sb, BARRIER);
4394  |
4395  |  /*
4396  |  * enable delayed allocation by default
4397  |  * Use -o nodelalloc to turn it off
4398  |  */
4399  |  if (!IS_EXT3_SB(sb) && !IS_EXT2_SB(sb) &&
4400  | 	    ((def_mount_opts & EXT4_DEFM_NODELALLOC) == 0))
4401  |  set_opt(sb, DELALLOC);
4402  |
4403  |  if (sb->s_blocksize <= PAGE_SIZE)
4404  |  set_opt(sb, DIOREAD_NOLOCK);
4405  | }
4406  |
4407  | static int ext4_handle_clustersize(struct super_block *sb)
4408  | {
4409  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
4410  |  struct ext4_super_block *es = sbi->s_es;
4411  |  int clustersize;
4412  |
4413  |  /* Handle clustersize */
4414  | 	clustersize = BLOCK_SIZE << le32_to_cpu(es->s_log_cluster_size);
4415  |  if (ext4_has_feature_bigalloc(sb)) {
4416  |  if (clustersize < sb->s_blocksize) {
4417  |  ext4_msg(sb, KERN_ERR,
4418  |  "cluster size (%d) smaller than "
4419  |  "block size (%lu)", clustersize, sb->s_blocksize);
4420  |  return -EINVAL;
4421  | 		}
4422  | 		sbi->s_cluster_bits = le32_to_cpu(es->s_log_cluster_size) -
4423  |  le32_to_cpu(es->s_log_block_size);
4424  | 	} else {
4425  |  if (clustersize != sb->s_blocksize) {
4426  |  ext4_msg(sb, KERN_ERR,
4427  |  "fragment/cluster size (%d) != "
4428  |  "block size (%lu)", clustersize, sb->s_blocksize);
4429  |  return -EINVAL;
4430  | 		}
4431  |  if (sbi->s_blocks_per_group > sb->s_blocksize * 8) {
4432  |  ext4_msg(sb, KERN_ERR,
4433  |  "#blocks per group too big: %lu",
4435  |  return -EINVAL;
4436  | 		}
4437  | 		sbi->s_cluster_bits = 0;
4438  | 	}
4439  | 	sbi->s_clusters_per_group = le32_to_cpu(es->s_clusters_per_group);
4440  |  if (sbi->s_clusters_per_group > sb->s_blocksize * 8) {
4441  |  ext4_msg(sb, KERN_ERR, "#clusters per group too big: %lu",
4442  |  sbi->s_clusters_per_group);
4443  |  return -EINVAL;
4444  | 	}
4445  |  if (sbi->s_blocks_per_group !=
4446  | 	    (sbi->s_clusters_per_group * (clustersize / sb->s_blocksize))) {
4447  |  ext4_msg(sb, KERN_ERR,
4448  |  "blocks per group (%lu) and clusters per group (%lu) inconsistent",
4449  |  sbi->s_blocks_per_group, sbi->s_clusters_per_group);
4450  |  return -EINVAL;
4451  | 	}
4452  | 	sbi->s_cluster_ratio = clustersize / sb->s_blocksize;
4453  |
4454  |  /* Do we have standard group size of clustersize * 8 blocks ? */
4455  |  if (sbi->s_blocks_per_group == clustersize << 3)
4456  |  set_opt2(sb, STD_GROUP_SIZE);
4457  |
4458  |  return 0;
4459  | }
4460  |
4461  | static void ext4_fast_commit_init(struct super_block *sb)
4462  | {
4463  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
4464  |
4465  |  /* Initialize fast commit stuff */
4466  | 	atomic_set(&sbi->s_fc_subtid, 0);
4467  | 	INIT_LIST_HEAD(&sbi->s_fc_q[FC_Q_MAIN]);
4468  | 	INIT_LIST_HEAD(&sbi->s_fc_q[FC_Q_STAGING]);
4469  | 	INIT_LIST_HEAD(&sbi->s_fc_dentry_q[FC_Q_MAIN]);
4470  | 	INIT_LIST_HEAD(&sbi->s_fc_dentry_q[FC_Q_STAGING]);
4471  | 	sbi->s_fc_bytes = 0;
4472  | 	ext4_clear_mount_flag(sb, EXT4_MF_FC_INELIGIBLE);
4473  | 	sbi->s_fc_ineligible_tid = 0;
4474  |  spin_lock_init(&sbi->s_fc_lock);
4475  |  memset(&sbi->s_fc_stats, 0, sizeof(sbi->s_fc_stats));
4476  | 	sbi->s_fc_replay_state.fc_regions = NULL;
4477  | 	sbi->s_fc_replay_state.fc_regions_size = 0;
4478  | 	sbi->s_fc_replay_state.fc_regions_used = 0;
4479  | 	sbi->s_fc_replay_state.fc_regions_valid = 0;
4480  | 	sbi->s_fc_replay_state.fc_modified_inodes = NULL;
4481  | 	sbi->s_fc_replay_state.fc_modified_inodes_size = 0;
4482  | 	sbi->s_fc_replay_state.fc_modified_inodes_used = 0;
4483  | }
4484  |
4485  | static int ext4_inode_info_init(struct super_block *sb,
4486  |  struct ext4_super_block *es)
4487  | {
4488  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
4489  |
4490  |  if (le32_to_cpu(es->s_rev_level) == EXT4_GOOD_OLD_REV) {
    8←Assuming field 's_rev_level' is not equal to EXT4_GOOD_OLD_REV→
    9←Taking false branch→
4491  | 		sbi->s_inode_size = EXT4_GOOD_OLD_INODE_SIZE;
4492  | 		sbi->s_first_ino = EXT4_GOOD_OLD_FIRST_INO;
4493  | 	} else {
4494  |  sbi->s_inode_size = le16_to_cpu(es->s_inode_size);
4495  | 		sbi->s_first_ino = le32_to_cpu(es->s_first_ino);
4496  |  if (sbi->s_first_ino < EXT4_GOOD_OLD_FIRST_INO) {
    10←Assuming field 's_first_ino' is >= EXT4_GOOD_OLD_FIRST_INO→
4497  |  ext4_msg(sb, KERN_ERR, "invalid first ino: %u",
4498  |  sbi->s_first_ino);
4499  |  return -EINVAL;
4500  | 		}
4501  |  if ((sbi->s_inode_size < EXT4_GOOD_OLD_INODE_SIZE) ||
    11←Assuming field 's_inode_size' is >= EXT4_GOOD_OLD_INODE_SIZE→
    13←Taking false branch→
4502  | 		    (!is_power_of_2(sbi->s_inode_size)) ||
4503  | 		    (sbi->s_inode_size > sb->s_blocksize)) {
    12←Assuming field 's_inode_size' is <= field 's_blocksize'→
4504  |  ext4_msg(sb, KERN_ERR,
4505  |  "unsupported inode size: %d",
4506  |  sbi->s_inode_size);
4507  |  ext4_msg(sb, KERN_ERR, "blocksize: %lu", sb->s_blocksize);
4508  |  return -EINVAL;
4509  | 		}
4510  |  /*
4511  |  * i_atime_extra is the last extra field available for
4512  |  * [acm]times in struct ext4_inode. Checking for that
4513  |  * field should suffice to ensure we have extra space
4514  |  * for all three.
4515  |  */
4516  |  if (sbi->s_inode_size >= offsetof(struct ext4_inode, i_atime_extra) +
    14←Assuming the condition is false→
    15←Taking false branch→
4517  |  sizeof(((struct ext4_inode *)0)->i_atime_extra)) {
4518  | 			sb->s_time_gran = 1;
4519  | 			sb->s_time_max = EXT4_EXTRA_TIMESTAMP_MAX;
4520  | 		} else {
4521  |  sb->s_time_gran = NSEC_PER_SEC;
4522  |  sb->s_time_max = EXT4_NON_EXTRA_TIMESTAMP_MAX;
4523  | 		}
4524  |  sb->s_time_min = EXT4_TIMESTAMP_MIN;
4525  | 	}
4526  |
4527  |  if (sbi->s_inode_size > EXT4_GOOD_OLD_INODE_SIZE) {
    16←Assuming field 's_inode_size' is > EXT4_GOOD_OLD_INODE_SIZE→
    17←Taking true branch→
4528  |  sbi->s_want_extra_isize = sizeof(struct ext4_inode) -
4529  |  EXT4_GOOD_OLD_INODE_SIZE;
4530  |  if (ext4_has_feature_extra_isize(sb)) {
    18←Taking true branch→
4531  |  unsigned v, max = (sbi->s_inode_size -
4532  |  EXT4_GOOD_OLD_INODE_SIZE);
4533  |
4534  | 			v = le16_to_cpu(es->s_want_extra_isize);
4535  |  if (v > max) {
    19←Assuming 'v' is <= 'max'→
    20←Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation
4536  |  ext4_msg(sb, KERN_ERR,
4537  |  "bad s_want_extra_isize: %d", v);
4538  |  return -EINVAL;
4539  | 			}
4540  |  if (sbi->s_want_extra_isize < v)
4541  | 				sbi->s_want_extra_isize = v;
4542  |
4543  | 			v = le16_to_cpu(es->s_min_extra_isize);
4544  |  if (v > max) {
4545  |  ext4_msg(sb, KERN_ERR,
4546  |  "bad s_min_extra_isize: %d", v);
4547  |  return -EINVAL;
4548  | 			}
4549  |  if (sbi->s_want_extra_isize < v)
4550  | 				sbi->s_want_extra_isize = v;
4551  | 		}
4552  | 	}
4553  |
4554  |  return 0;
4555  | }
4556  |
4557  | #if IS_ENABLED(CONFIG_UNICODE)
4558  | static int ext4_encoding_init(struct super_block *sb, struct ext4_super_block *es)
4559  | {
4560  |  const struct ext4_sb_encodings *encoding_info;
4561  |  struct unicode_map *encoding;
4562  | 	__u16 encoding_flags = le16_to_cpu(es->s_encoding_flags);
4563  |
4564  |  if (!ext4_has_feature_casefold(sb) || sb->s_encoding)
4565  |  return 0;
4566  |
4567  | 	encoding_info = ext4_sb_read_encoding(es);
4568  |  if (!encoding_info) {
4569  |  ext4_msg(sb, KERN_ERR,
4570  |  "Encoding requested by superblock is unknown");
4571  |  return -EINVAL;
4572  | 	}
4573  |
4574  | 	encoding = utf8_load(encoding_info->version);
4575  |  if (IS_ERR(encoding)) {
4576  |  ext4_msg(sb, KERN_ERR,
4577  |  "can't mount with superblock charset: %s-%u.%u.%u "
4578  |  "not supported by the kernel. flags: 0x%x.",
4579  |  encoding_info->name,
4580  |  unicode_major(encoding_info->version),
4581  |  unicode_minor(encoding_info->version),
4582  |  unicode_rev(encoding_info->version),
4583  |  encoding_flags);
4584  |  return -EINVAL;
4585  | 	}
4586  |  ext4_msg(sb, KERN_INFO,"Using encoding defined by superblock: "
4587  |  "%s-%u.%u.%u with flags 0x%hx", encoding_info->name,
4588  |  unicode_major(encoding_info->version),
4589  |  unicode_minor(encoding_info->version),
4590  |  unicode_rev(encoding_info->version),
4591  |  encoding_flags);
4592  |
4593  | 	sb->s_encoding = encoding;
4594  | 	sb->s_encoding_flags = encoding_flags;
4595  |
4596  |  return 0;
4597  | }
4598  | #else
4599  | static inline int ext4_encoding_init(struct super_block *sb, struct ext4_super_block *es)
4600  | {
4601  |  return 0;
4602  | }
4603  | #endif
4604  |
4605  | static int ext4_init_metadata_csum(struct super_block *sb, struct ext4_super_block *es)
4606  | {
4607  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
4608  |
4609  |  /* Warn if metadata_csum and gdt_csum are both set. */
4610  |  if (ext4_has_feature_metadata_csum(sb) &&
4611  | 	    ext4_has_feature_gdt_csum(sb))
4612  |  ext4_warning(sb, "metadata_csum and uninit_bg are "
4613  |  "redundant flags; please run fsck.");
4614  |
4615  |  /* Check for a known checksum algorithm */
4616  |  if (!ext4_verify_csum_type(sb, es)) {
4617  |  ext4_msg(sb, KERN_ERR, "VFS: Found ext4 filesystem with "
4618  |  "unknown checksum algorithm.");
4619  |  return -EINVAL;
4620  | 	}
4621  | 	ext4_setup_csum_trigger(sb, EXT4_JTR_ORPHAN_FILE,
4622  | 				ext4_orphan_file_block_trigger);
4623  |
4624  |  /* Load the checksum driver */
4625  | 	sbi->s_chksum_driver = crypto_alloc_shash("crc32c", 0, 0);
4626  |  if (IS_ERR(sbi->s_chksum_driver)) {
4627  |  int ret = PTR_ERR(sbi->s_chksum_driver);
4628  |  ext4_msg(sb, KERN_ERR, "Cannot load crc32c driver.");
4629  | 		sbi->s_chksum_driver = NULL;
4630  |  return ret;
4631  | 	}
4632  |
4633  |  /* Check superblock checksum */
4634  |  if (!ext4_superblock_csum_verify(sb, es)) {
4635  |  ext4_msg(sb, KERN_ERR, "VFS: Found ext4 filesystem with "
4636  |  "invalid superblock checksum.  Run e2fsck?");
4637  |  return -EFSBADCRC;
4638  | 	}
4639  |
4640  |  /* Precompute checksum seed for all metadata */
4641  |  if (ext4_has_feature_csum_seed(sb))
4642  | 		sbi->s_csum_seed = le32_to_cpu(es->s_checksum_seed);
4643  |  else if (ext4_has_metadata_csum(sb) || ext4_has_feature_ea_inode(sb))
4644  | 		sbi->s_csum_seed = ext4_chksum(sbi, ~0, es->s_uuid,
4645  |  sizeof(es->s_uuid));
4646  |  return 0;
4647  | }
4648  |
4649  | static int ext4_check_feature_compatibility(struct super_block *sb,
4650  |  struct ext4_super_block *es,
4651  |  int silent)
4652  | {
4653  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
4654  |
4655  |  if (le32_to_cpu(es->s_rev_level) == EXT4_GOOD_OLD_REV &&
4656  | 	    (ext4_has_compat_features(sb) ||
4657  | 	     ext4_has_ro_compat_features(sb) ||
4658  | 	     ext4_has_incompat_features(sb)))
4659  |  ext4_msg(sb, KERN_WARNING,
4660  |  "feature flags set on rev 0 fs, "
4661  |  "running e2fsck is recommended");
4662  |
4663  |  if (es->s_creator_os == cpu_to_le32(EXT4_OS_HURD)) {
4664  |  set_opt2(sb, HURD_COMPAT);
4665  |  if (ext4_has_feature_64bit(sb)) {
4666  |  ext4_msg(sb, KERN_ERR,
4667  |  "The Hurd can't support 64-bit file systems");
4668  |  return -EINVAL;
4669  | 		}
4670  |
4671  |  /*
4672  |  * ea_inode feature uses l_i_version field which is not
4673  |  * available in HURD_COMPAT mode.
4674  |  */
4675  |  if (ext4_has_feature_ea_inode(sb)) {
4676  |  ext4_msg(sb, KERN_ERR,
4964  | 	set_task_ioprio(sbi->s_journal->j_task, ctx->journal_ioprio);
4965  |
4966  | 	sbi->s_journal->j_submit_inode_data_buffers =
4967  | 		ext4_journal_submit_inode_data_buffers;
4968  | 	sbi->s_journal->j_finish_inode_data_buffers =
4969  | 		ext4_journal_finish_inode_data_buffers;
4970  |
4971  |  return 0;
4972  |
4973  | out:
4974  |  /* flush s_sb_upd_work before destroying the journal. */
4975  | 	flush_work(&sbi->s_sb_upd_work);
4976  | 	jbd2_journal_destroy(sbi->s_journal);
4977  | 	sbi->s_journal = NULL;
4978  |  return -EINVAL;
4979  | }
4980  |
4981  | static int ext4_check_journal_data_mode(struct super_block *sb)
4982  | {
4983  |  if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA) {
4984  |  printk_once(KERN_WARNING "EXT4-fs: Warning: mounting with "
4985  |  "data=journal disables delayed allocation, "
4986  |  "dioread_nolock, O_DIRECT and fast_commit support!\n");
4987  |  /* can't mount with both data=journal and dioread_nolock. */
4988  |  clear_opt(sb, DIOREAD_NOLOCK);
4989  |  clear_opt2(sb, JOURNAL_FAST_COMMIT);
4990  |  if (test_opt2(sb, EXPLICIT_DELALLOC)) {
4991  |  ext4_msg(sb, KERN_ERR, "can't mount with "
4992  |  "both data=journal and delalloc");
4993  |  return -EINVAL;
4994  | 		}
4995  |  if (test_opt(sb, DAX_ALWAYS)) {
4996  |  ext4_msg(sb, KERN_ERR, "can't mount with "
4997  |  "both data=journal and dax");
4998  |  return -EINVAL;
4999  | 		}
5000  |  if (ext4_has_feature_encrypt(sb)) {
5001  |  ext4_msg(sb, KERN_WARNING,
5002  |  "encrypted files will use data=ordered "
5003  |  "instead of data journaling mode");
5004  | 		}
5005  |  if (test_opt(sb, DELALLOC))
5006  |  clear_opt(sb, DELALLOC);
5007  | 	} else {
5008  | 		sb->s_iflags |= SB_I_CGROUPWB;
5009  | 	}
5010  |
5011  |  return 0;
5012  | }
5013  |
5014  | static int ext4_load_super(struct super_block *sb, ext4_fsblk_t *lsb,
5015  |  int silent)
5016  | {
5017  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
5018  |  struct ext4_super_block *es;
5019  | 	ext4_fsblk_t logical_sb_block;
5020  |  unsigned long offset = 0;
5021  |  struct buffer_head *bh;
5022  |  int ret = -EINVAL;
5023  |  int blocksize;
5024  |
5025  | 	blocksize = sb_min_blocksize(sb, EXT4_MIN_BLOCK_SIZE);
5026  |  if (!blocksize) {
5027  |  ext4_msg(sb, KERN_ERR, "unable to set blocksize");
5028  |  return -EINVAL;
5029  | 	}
5030  |
5031  |  /*
5032  |  * The ext4 superblock will not be buffer aligned for other than 1kB
5033  |  * block sizes.  We need to calculate the offset from buffer start.
5034  |  */
5035  |  if (blocksize != EXT4_MIN_BLOCK_SIZE) {
5036  | 		logical_sb_block = sbi->s_sb_block * EXT4_MIN_BLOCK_SIZE;
5037  | 		offset = do_div(logical_sb_block, blocksize);
5038  | 	} else {
5039  | 		logical_sb_block = sbi->s_sb_block;
5040  | 	}
5041  |
5042  | 	bh = ext4_sb_bread_unmovable(sb, logical_sb_block);
5043  |  if (IS_ERR(bh)) {
5044  |  ext4_msg(sb, KERN_ERR, "unable to read superblock");
5045  |  return PTR_ERR(bh);
5046  | 	}
5047  |  /*
5048  |  * Note: s_es must be initialized as soon as possible because
5049  |  *       some ext4 macro-instructions depend on its value
5050  |  */
5051  | 	es = (struct ext4_super_block *) (bh->b_data + offset);
5052  | 	sbi->s_es = es;
5053  | 	sb->s_magic = le16_to_cpu(es->s_magic);
5054  |  if (sb->s_magic != EXT4_SUPER_MAGIC) {
5055  |  if (!silent)
5056  |  ext4_msg(sb, KERN_ERR, "VFS: Can't find ext4 filesystem");
5057  |  goto out;
5058  | 	}
5059  |
5060  |  if (le32_to_cpu(es->s_log_block_size) >
5061  | 	    (EXT4_MAX_BLOCK_LOG_SIZE - EXT4_MIN_BLOCK_LOG_SIZE)) {
5062  |  ext4_msg(sb, KERN_ERR,
5063  |  "Invalid log block size: %u",
5064  |  le32_to_cpu(es->s_log_block_size));
5065  |  goto out;
5066  | 	}
5067  |  if (le32_to_cpu(es->s_log_cluster_size) >
5068  | 	    (EXT4_MAX_CLUSTER_LOG_SIZE - EXT4_MIN_BLOCK_LOG_SIZE)) {
5069  |  ext4_msg(sb, KERN_ERR,
5070  |  "Invalid log cluster size: %u",
5071  |  le32_to_cpu(es->s_log_cluster_size));
5072  |  goto out;
5073  | 	}
5074  |
5075  | 	blocksize = EXT4_MIN_BLOCK_SIZE << le32_to_cpu(es->s_log_block_size);
5076  |
5077  |  /*
5078  |  * If the default block size is not the same as the real block size,
5079  |  * we need to reload it.
5080  |  */
5081  |  if (sb->s_blocksize == blocksize) {
5082  | 		*lsb = logical_sb_block;
5083  | 		sbi->s_sbh = bh;
5084  |  return 0;
5085  | 	}
5086  |
5087  |  /*
5088  |  * bh must be released before kill_bdev(), otherwise
5089  |  * it won't be freed and its page also. kill_bdev()
5090  |  * is called by sb_set_blocksize().
5091  |  */
5092  | 	brelse(bh);
5093  |  /* Validate the filesystem blocksize */
5094  |  if (!sb_set_blocksize(sb, blocksize)) {
5095  |  ext4_msg(sb, KERN_ERR, "bad block size %d",
5096  |  blocksize);
5097  | 		bh = NULL;
5098  |  goto out;
5099  | 	}
5100  |
5101  | 	logical_sb_block = sbi->s_sb_block * EXT4_MIN_BLOCK_SIZE;
5102  | 	offset = do_div(logical_sb_block, blocksize);
5103  | 	bh = ext4_sb_bread_unmovable(sb, logical_sb_block);
5104  |  if (IS_ERR(bh)) {
5105  |  ext4_msg(sb, KERN_ERR, "Can't read superblock on 2nd try");
5106  | 		ret = PTR_ERR(bh);
5107  | 		bh = NULL;
5108  |  goto out;
5109  | 	}
5110  | 	es = (struct ext4_super_block *)(bh->b_data + offset);
5111  | 	sbi->s_es = es;
5112  |  if (es->s_magic != cpu_to_le16(EXT4_SUPER_MAGIC)) {
5113  |  ext4_msg(sb, KERN_ERR, "Magic mismatch, very weird!");
5114  |  goto out;
5152  |
5153  | static int ext4_block_group_meta_init(struct super_block *sb, int silent)
5154  | {
5155  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
5156  |  struct ext4_super_block *es = sbi->s_es;
5157  |  int has_huge_files;
5158  |
5159  | 	has_huge_files = ext4_has_feature_huge_file(sb);
5160  | 	sbi->s_bitmap_maxbytes = ext4_max_bitmap_size(sb->s_blocksize_bits,
5161  | 						      has_huge_files);
5162  | 	sb->s_maxbytes = ext4_max_size(sb->s_blocksize_bits, has_huge_files);
5163  |
5164  | 	sbi->s_desc_size = le16_to_cpu(es->s_desc_size);
5165  |  if (ext4_has_feature_64bit(sb)) {
5166  |  if (sbi->s_desc_size < EXT4_MIN_DESC_SIZE_64BIT ||
5167  | 		    sbi->s_desc_size > EXT4_MAX_DESC_SIZE ||
5168  | 		    !is_power_of_2(sbi->s_desc_size)) {
5169  |  ext4_msg(sb, KERN_ERR,
5170  |  "unsupported descriptor size %lu",
5171  |  sbi->s_desc_size);
5172  |  return -EINVAL;
5173  | 		}
5174  | 	} else
5175  | 		sbi->s_desc_size = EXT4_MIN_DESC_SIZE;
5176  |
5177  | 	sbi->s_blocks_per_group = le32_to_cpu(es->s_blocks_per_group);
5178  | 	sbi->s_inodes_per_group = le32_to_cpu(es->s_inodes_per_group);
5179  |
5180  | 	sbi->s_inodes_per_block = sb->s_blocksize / EXT4_INODE_SIZE(sb);
5181  |  if (sbi->s_inodes_per_block == 0 || sbi->s_blocks_per_group == 0) {
5182  |  if (!silent)
5183  |  ext4_msg(sb, KERN_ERR, "VFS: Can't find ext4 filesystem");
5184  |  return -EINVAL;
5185  | 	}
5186  |  if (sbi->s_inodes_per_group < sbi->s_inodes_per_block ||
5187  | 	    sbi->s_inodes_per_group > sb->s_blocksize * 8) {
5188  |  ext4_msg(sb, KERN_ERR, "invalid inodes per group: %lu\n",
5189  |  sbi->s_inodes_per_group);
5190  |  return -EINVAL;
5191  | 	}
5192  | 	sbi->s_itb_per_group = sbi->s_inodes_per_group /
5193  | 					sbi->s_inodes_per_block;
5194  | 	sbi->s_desc_per_block = sb->s_blocksize / EXT4_DESC_SIZE(sb);
5195  | 	sbi->s_mount_state = le16_to_cpu(es->s_state) & ~EXT4_FC_REPLAY;
5196  | 	sbi->s_addr_per_block_bits = ilog2(EXT4_ADDR_PER_BLOCK(sb));
5197  | 	sbi->s_desc_per_block_bits = ilog2(EXT4_DESC_PER_BLOCK(sb));
5198  |
5199  |  return 0;
5200  | }
5201  |
5202  | static int __ext4_fill_super(struct fs_context *fc, struct super_block *sb)
5203  | {
5204  |  struct ext4_super_block *es = NULL;
5205  |  struct ext4_sb_info *sbi = EXT4_SB(sb);
5206  | 	ext4_fsblk_t logical_sb_block;
5207  |  struct inode *root;
5208  |  int needs_recovery;
5209  |  int err;
5210  | 	ext4_group_t first_not_zeroed;
5211  |  struct ext4_fs_context *ctx = fc->fs_private;
5212  |  int silent = fc->sb_flags & SB_SILENT;
5213  |
5214  |  /* Set defaults for the variables that will be set during parsing */
5215  |  if (!(ctx->spec & EXT4_SPEC_JOURNAL_IOPRIO))
    1Assuming the condition is false→
    2←Taking false branch→
5216  | 		ctx->journal_ioprio = DEFAULT_JOURNAL_IOPRIO;
5217  |
5218  |  sbi->s_inode_readahead_blks = EXT4_DEF_INODE_READAHEAD_BLKS;
5219  | 	sbi->s_sectors_written_start =
5220  |  part_stat_read(sb->s_bdev, sectors[STAT_WRITE]);
    3←Assuming '_cpu' is >= 'nr_cpu_ids'→
    4←Loop condition is false. Execution continues on line 5220→
5221  |
5222  |  err = ext4_load_super(sb, &logical_sb_block, silent);
5223  |  if (err4.1'err' is 0)
    5←Taking false branch→
5224  |  goto out_fail;
5225  |
5226  |  es = sbi->s_es;
5227  | 	sbi->s_kbytes_written = le64_to_cpu(es->s_kbytes_written);
5228  |
5229  | 	err = ext4_init_metadata_csum(sb, es);
5230  |  if (err5.1'err' is 0)
    6←Taking false branch→
5231  |  goto failed_mount;
5232  |
5233  |  ext4_set_def_opts(sb, es);
5234  |
5235  | 	sbi->s_resuid = make_kuid(&init_user_ns, le16_to_cpu(es->s_def_resuid));
5236  | 	sbi->s_resgid = make_kgid(&init_user_ns, le16_to_cpu(es->s_def_resgid));
5237  | 	sbi->s_commit_interval = JBD2_DEFAULT_MAX_COMMIT_AGE * HZ;
5238  | 	sbi->s_min_batch_time = EXT4_DEF_MIN_BATCH_TIME;
5239  | 	sbi->s_max_batch_time = EXT4_DEF_MAX_BATCH_TIME;
5240  |
5241  |  /*
5242  |  * set default s_li_wait_mult for lazyinit, for the case there is
5243  |  * no mount option specified.
5244  |  */
5245  | 	sbi->s_li_wait_mult = EXT4_DEF_LI_WAIT_MULT;
5246  |
5247  |  err = ext4_inode_info_init(sb, es);
    7←Calling 'ext4_inode_info_init'→
5248  |  if (err)
5249  |  goto failed_mount;
5250  |
5251  | 	err = parse_apply_sb_mount_options(sb, ctx);
5252  |  if (err < 0)
5253  |  goto failed_mount;
5254  |
5255  | 	sbi->s_def_mount_opt = sbi->s_mount_opt;
5256  | 	sbi->s_def_mount_opt2 = sbi->s_mount_opt2;
5257  |
5258  | 	err = ext4_check_opt_consistency(fc, sb);
5259  |  if (err < 0)
5260  |  goto failed_mount;
5261  |
5262  | 	ext4_apply_options(fc, sb);
5263  |
5264  | 	err = ext4_encoding_init(sb, es);
5265  |  if (err)
5266  |  goto failed_mount;
5267  |
5268  | 	err = ext4_check_journal_data_mode(sb);
5269  |  if (err)
5270  |  goto failed_mount;
5271  |
5272  | 	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) |
5273  | 		(test_opt(sb, POSIX_ACL) ? SB_POSIXACL : 0);
5274  |
5275  |  /* i_version is always enabled now */
5276  | 	sb->s_flags |= SB_I_VERSION;
5277  |

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
