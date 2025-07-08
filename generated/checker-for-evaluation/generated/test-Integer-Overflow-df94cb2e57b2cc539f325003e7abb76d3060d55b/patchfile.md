## Patch Description

bcachefs: Fix an integer overflow

Fixes:

bcachefs (e7fdc10e-54a3-49d9-bd0c-390370889d84): disk usage increased 4294967296 more than 2823707312 sectors reserved)
transaction updates for __bchfs_fallocate journal seq 467859
  update: btree=extents cached=0 bch2_trans_update+0x4e8/0x540
    old u64s 5 type deleted 536925940:3559337304:4294967283 len 0 ver 0
    new u64s 6 type reservation 536925940:3559337304:4294967283 len 3559337304 ver 0: generation 0 replicas 2
  update: btree=inodes cached=1 bch2_extent_update_i_size_sectors+0x305/0x3b0
    old u64s 19 type inode_v3 0:536925940:4294967283 len 0 ver 0: mode 100600 flags 15300000 journal_seq 467859 bi_size 0 bi_sectors 0 bi_version 0 bi_atime 40905301656446 bi_ctime 40905301656446 bi_mtime 40905301656446 bi_otime 40905301656446 bi_uid 0 bi_gid 0 bi_nlink 0 bi_generation 0 bi_dev 0 bi_data_checksum 0 bi_compression 0 bi_project 0 bi_background_compression 0 bi_data_replicas 0 bi_promote_target 0 bi_foreground_target 0 bi_background_target 0 bi_erasure_code 0 bi_fields_set 0 bi_dir 1879048193 bi_dir_offset 3384856038735393365 bi_subvol 0 bi_parent_subvol 0 bi_nocow 0
    new u64s 19 type inode_v3 0:536925940:4294967283 len 0 ver 0: mode 100600 flags 15300000 journal_seq 467859 bi_size 0 bi_sectors 3559337304 bi_version 0 bi_atime 40905301656446 bi_ctime 40905301656446 bi_mtime 40905301656446 bi_otime 40905301656446 bi_uid 0 bi_gid 0 bi_nlink 0 bi_generation 0 bi_dev 0 bi_data_checksum 0 bi_compression 0 bi_project 0 bi_background_compression 0 bi_data_replicas 0 bi_promote_target 0 bi_foreground_target 0 bi_background_target 0 bi_erasure_code 0 bi_fields_set 0 bi_dir 1879048193 bi_dir_offset 3384856038735393365 bi_subvol 0 bi_parent_subvol 0 bi_nocow 0

Kernel panic - not syncing: bcachefs (e7fdc10e-54a3-49d9-bd0c-390370889d84): panic after error
CPU: 4 PID: 5154 Comm: rsync Not tainted 6.5.9-gateway-gca1614174cc0-dirty #1
Hardware name: To Be Filled By O.E.M. To Be Filled By O.E.M./X570 Phantom Gaming 4, BIOS P4.20 08/02/2021
Call Trace:
 <TASK>
 dump_stack_lvl+0x5a/0x90
 panic+0x105/0x300
 ? console_unlock+0xf1/0x130
 ? bch2_printbuf_exit+0x16/0x30
 ? srso_return_thunk+0x5/0x10
 bch2_inconsistent_error+0x6f/0x80
 bch2_trans_fs_usage_apply+0x279/0x3d0
 __bch2_trans_commit+0x112a/0x1df0
 ? bch2_extent_update+0x13a/0x1d0
 bch2_extent_update+0x13a/0x1d0
 bch2_extent_fallocate+0x58e/0x740
 bch2_fallocate_dispatch+0xb7c/0x1030
 ? do_filp_open+0xa0/0x140
 vfs_fallocate+0x18e/0x1d0
 __x64_sys_fallocate+0x46/0x70
 do_syscall_64+0x48/0xa0
 ? exit_to_user_mode_prepare+0x4d/0xa0
 entry_SYSCALL_64_after_hwframe+0x6e/0xd8
RIP: 0033:0x7fc85d91bbb3
Code: 64 89 02 b8 ff ff ff ff eb bd 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 80 3d 31 da 0d 00 00 49 89 ca 74 14 b8 1d 01 00 00 0f 05 <48> 3d 00 f0 ff ff 77 5d c3 0f 1f 40 00 48 83 ec 28 48 89 54 24 10

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

## Buggy Code

```c
// fs/bcachefs/buckets.c
int bch2_trans_fs_usage_apply(struct btree_trans *trans,
			      struct replicas_delta_list *deltas)
{
	struct bch_fs *c = trans->c;
	static int warned_disk_usage = 0;
	bool warn = false;
	unsigned disk_res_sectors = trans->disk_res ? trans->disk_res->sectors : 0;
	struct replicas_delta *d, *d2;
	struct replicas_delta *top = (void *) deltas->d + deltas->used;
	struct bch_fs_usage *dst;
	s64 added = 0, should_not_have_added;
	unsigned i;

	percpu_down_read(&c->mark_lock);
	preempt_disable();
	dst = fs_usage_ptr(c, trans->journal_res.seq, false);

	for (d = deltas->d; d != top; d = replicas_delta_next(d)) {
		switch (d->r.data_type) {
		case BCH_DATA_btree:
		case BCH_DATA_user:
		case BCH_DATA_parity:
			added += d->delta;
		}

		if (__update_replicas(c, dst, &d->r, d->delta))
			goto need_mark;
	}

	dst->nr_inodes += deltas->nr_inodes;

	for (i = 0; i < BCH_REPLICAS_MAX; i++) {
		added				+= deltas->persistent_reserved[i];
		dst->reserved			+= deltas->persistent_reserved[i];
		dst->persistent_reserved[i]	+= deltas->persistent_reserved[i];
	}

	/*
	 * Not allowed to reduce sectors_available except by getting a
	 * reservation:
	 */
	should_not_have_added = added - (s64) disk_res_sectors;
	if (unlikely(should_not_have_added > 0)) {
		u64 old, new, v = atomic64_read(&c->sectors_available);

		do {
			old = v;
			new = max_t(s64, 0, old - should_not_have_added);
		} while ((v = atomic64_cmpxchg(&c->sectors_available,
					       old, new)) != old);

		added -= should_not_have_added;
		warn = true;
	}

	if (added > 0) {
		trans->disk_res->sectors -= added;
		this_cpu_sub(*c->online_reserved, added);
	}

	preempt_enable();
	percpu_up_read(&c->mark_lock);

	if (unlikely(warn) && !xchg(&warned_disk_usage, 1))
		bch2_trans_inconsistent(trans,
					"disk usage increased %lli more than %u sectors reserved)",
					should_not_have_added, disk_res_sectors);
	return 0;
need_mark:
	/* revert changes: */
	for (d2 = deltas->d; d2 != d; d2 = replicas_delta_next(d2))
		BUG_ON(__update_replicas(c, dst, &d2->r, -d2->delta));

	preempt_enable();
	percpu_up_read(&c->mark_lock);
	return -1;
}
```
```c
// fs/bcachefs/io_misc.c
int bch2_extent_fallocate(struct btree_trans *trans,
			  subvol_inum inum,
			  struct btree_iter *iter,
			  unsigned sectors,
			  struct bch_io_opts opts,
			  s64 *i_sectors_delta,
			  struct write_point_specifier write_point)
{
	struct bch_fs *c = trans->c;
	struct disk_reservation disk_res = { 0 };
	struct closure cl;
	struct open_buckets open_buckets = { 0 };
	struct bkey_s_c k;
	struct bkey_buf old, new;
	unsigned sectors_allocated = 0;
	bool have_reservation = false;
	bool unwritten = opts.nocow &&
	    c->sb.version >= bcachefs_metadata_version_unwritten_extents;
	int ret;

	bch2_bkey_buf_init(&old);
	bch2_bkey_buf_init(&new);
	closure_init_stack(&cl);

	k = bch2_btree_iter_peek_slot(iter);
	ret = bkey_err(k);
	if (ret)
		return ret;

	sectors = min_t(u64, sectors, k.k->p.offset - iter->pos.offset);

	if (!have_reservation) {
		unsigned new_replicas =
			max(0, (int) opts.data_replicas -
			    (int) bch2_bkey_nr_ptrs_fully_allocated(k));
		/*
		 * Get a disk reservation before (in the nocow case) calling
		 * into the allocator:
		 */
		ret = bch2_disk_reservation_get(c, &disk_res, sectors, new_replicas, 0);
		if (unlikely(ret))
			goto err;

		bch2_bkey_buf_reassemble(&old, c, k);
	}

	if (have_reservation) {
		if (!bch2_extents_match(k, bkey_i_to_s_c(old.k)))
			goto err;

		bch2_key_resize(&new.k->k, sectors);
	} else if (!unwritten) {
		struct bkey_i_reservation *reservation;

		bch2_bkey_buf_realloc(&new, c, sizeof(*reservation) / sizeof(u64));
		reservation = bkey_reservation_init(new.k);
		reservation->k.p = iter->pos;
		bch2_key_resize(&reservation->k, sectors);
		reservation->v.nr_replicas = opts.data_replicas;
	} else {
		struct bkey_i_extent *e;
		struct bch_devs_list devs_have;
		struct write_point *wp;
		struct bch_extent_ptr *ptr;

		devs_have.nr = 0;

		bch2_bkey_buf_realloc(&new, c, BKEY_EXTENT_U64s_MAX);

		e = bkey_extent_init(new.k);
		e->k.p = iter->pos;

		ret = bch2_alloc_sectors_start_trans(trans,
				opts.foreground_target,
				false,
				write_point,
				&devs_have,
				opts.data_replicas,
				opts.data_replicas,
				BCH_WATERMARK_normal, 0, &cl, &wp);
		if (bch2_err_matches(ret, BCH_ERR_operation_blocked))
			ret = -BCH_ERR_transaction_restart_nested;
		if (ret)
			goto err;

		sectors = min(sectors, wp->sectors_free);
		sectors_allocated = sectors;

		bch2_key_resize(&e->k, sectors);

		bch2_open_bucket_get(c, wp, &open_buckets);
		bch2_alloc_sectors_append_ptrs(c, wp, &e->k_i, sectors, false);
		bch2_alloc_sectors_done(c, wp);

		extent_for_each_ptr(extent_i_to_s(e), ptr)
			ptr->unwritten = true;
	}

	have_reservation = true;

	ret = bch2_extent_update(trans, inum, iter, new.k, &disk_res,
				 0, i_sectors_delta, true);
err:
	if (!ret && sectors_allocated)
		bch2_increment_clock(c, sectors_allocated, WRITE);

	bch2_open_buckets_put(c, &open_buckets);
	bch2_disk_reservation_put(c, &disk_res);
	bch2_bkey_buf_exit(&new, c);
	bch2_bkey_buf_exit(&old, c);

	if (closure_nr_remaining(&cl) != 1) {
		bch2_trans_unlock(trans);
		closure_sync(&cl);
	}

	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/bcachefs/buckets.c b/fs/bcachefs/buckets.c
index 2acd727d3f9b..58d8c6ffd955 100644
--- a/fs/bcachefs/buckets.c
+++ b/fs/bcachefs/buckets.c
@@ -1322,7 +1322,7 @@ int bch2_trans_fs_usage_apply(struct btree_trans *trans,
 	struct bch_fs *c = trans->c;
 	static int warned_disk_usage = 0;
 	bool warn = false;
-	unsigned disk_res_sectors = trans->disk_res ? trans->disk_res->sectors : 0;
+	u64 disk_res_sectors = trans->disk_res ? trans->disk_res->sectors : 0;
 	struct replicas_delta *d, *d2;
 	struct replicas_delta *top = (void *) deltas->d + deltas->used;
 	struct bch_fs_usage *dst;
@@ -1381,7 +1381,7 @@ int bch2_trans_fs_usage_apply(struct btree_trans *trans,
 
 	if (unlikely(warn) && !xchg(&warned_disk_usage, 1))
 		bch2_trans_inconsistent(trans,
-					"disk usage increased %lli more than %u sectors reserved)",
+					"disk usage increased %lli more than %llu sectors reserved)",
 					should_not_have_added, disk_res_sectors);
 	return 0;
 need_mark:
diff --git a/fs/bcachefs/io_misc.c b/fs/bcachefs/io_misc.c
index 0979d5e05713..bebc11444ef5 100644
--- a/fs/bcachefs/io_misc.c
+++ b/fs/bcachefs/io_misc.c
@@ -23,7 +23,7 @@
 int bch2_extent_fallocate(struct btree_trans *trans,
 			  subvol_inum inum,
 			  struct btree_iter *iter,
-			  unsigned sectors,
+			  u64 sectors,
 			  struct bch_io_opts opts,
 			  s64 *i_sectors_delta,
 			  struct write_point_specifier write_point)
@@ -105,7 +105,7 @@ int bch2_extent_fallocate(struct btree_trans *trans,
 		if (ret)
 			goto err;
 
-		sectors = min(sectors, wp->sectors_free);
+		sectors = min_t(u64, sectors, wp->sectors_free);
 		sectors_allocated = sectors;
 
 		bch2_key_resize(&e->k, sectors);
diff --git a/fs/bcachefs/io_misc.h b/fs/bcachefs/io_misc.h
index c9e6ed40e1b8..9cb44a7c43c1 100644
--- a/fs/bcachefs/io_misc.h
+++ b/fs/bcachefs/io_misc.h
@@ -3,7 +3,7 @@
 #define _BCACHEFS_IO_MISC_H
 
 int bch2_extent_fallocate(struct btree_trans *, subvol_inum, struct btree_iter *,
-			  unsigned, struct bch_io_opts, s64 *,
+			  u64, struct bch_io_opts, s64 *,
 			  struct write_point_specifier);
 int bch2_fpunch_at(struct btree_trans *, struct btree_iter *,
 		   subvol_inum, u64, s64 *);
```

