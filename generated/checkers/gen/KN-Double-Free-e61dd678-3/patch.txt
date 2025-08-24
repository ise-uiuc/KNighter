## Patch Description

bcachefs: Fix double free of ca->buckets_nouse

Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Fixes: ffcbec6076 ("bcachefs: Kill opts.buckets_nouse")
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

## Buggy Code

```c
// Function: bch2_dev_free in fs/bcachefs/super.c
static void bch2_dev_free(struct bch_dev *ca)
{
	cancel_work_sync(&ca->io_error_work);

	if (ca->kobj.state_in_sysfs &&
	    ca->disk_sb.bdev)
		sysfs_remove_link(bdev_kobj(ca->disk_sb.bdev), "bcachefs");

	if (ca->kobj.state_in_sysfs)
		kobject_del(&ca->kobj);

	kfree(ca->buckets_nouse);
	bch2_free_super(&ca->disk_sb);
	bch2_dev_allocator_background_exit(ca);
	bch2_dev_journal_exit(ca);

	free_percpu(ca->io_done);
	bch2_dev_buckets_free(ca);
	free_page((unsigned long) ca->sb_read_scratch);

	bch2_time_stats_quantiles_exit(&ca->io_latency[WRITE]);
	bch2_time_stats_quantiles_exit(&ca->io_latency[READ]);

	percpu_ref_exit(&ca->io_ref);
#ifndef CONFIG_BCACHEFS_DEBUG
	percpu_ref_exit(&ca->ref);
#endif
	kobject_put(&ca->kobj);
}
```

## Bug Fix Patch

```diff
diff --git a/fs/bcachefs/super.c b/fs/bcachefs/super.c
index 0455a1001fec..e7fa2de35014 100644
--- a/fs/bcachefs/super.c
+++ b/fs/bcachefs/super.c
@@ -1193,7 +1193,6 @@ static void bch2_dev_free(struct bch_dev *ca)
 	if (ca->kobj.state_in_sysfs)
 		kobject_del(&ca->kobj);

-	kfree(ca->buckets_nouse);
 	bch2_free_super(&ca->disk_sb);
 	bch2_dev_allocator_background_exit(ca);
 	bch2_dev_journal_exit(ca);
```
