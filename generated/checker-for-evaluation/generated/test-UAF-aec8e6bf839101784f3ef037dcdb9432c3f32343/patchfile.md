## Patch Description

btrfs: fix use-after-free of block device file in __btrfs_free_extra_devids()

Mounting btrfs from two images (which have the same one fsid and two
different dev_uuids) in certain executing order may trigger an UAF for
variable 'device->bdev_file' in __btrfs_free_extra_devids(). And
following are the details:

1. Attach image_1 to loop0, attach image_2 to loop1, and scan btrfs
   devices by ioctl(BTRFS_IOC_SCAN_DEV):

             /  btrfs_device_1 → loop0
   fs_device
             \  btrfs_device_2 → loop1
2. mount /dev/loop0 /mnt
   btrfs_open_devices
    btrfs_device_1->bdev_file = btrfs_get_bdev_and_sb(loop0)
    btrfs_device_2->bdev_file = btrfs_get_bdev_and_sb(loop1)
   btrfs_fill_super
    open_ctree
     fail: btrfs_close_devices // -ENOMEM
	    btrfs_close_bdev(btrfs_device_1)
             fput(btrfs_device_1->bdev_file)
	      // btrfs_device_1->bdev_file is freed
	    btrfs_close_bdev(btrfs_device_2)
             fput(btrfs_device_2->bdev_file)

3. mount /dev/loop1 /mnt
   btrfs_open_devices
    btrfs_get_bdev_and_sb(&bdev_file)
     // EIO, btrfs_device_1->bdev_file is not assigned,
     // which points to a freed memory area
    btrfs_device_2->bdev_file = btrfs_get_bdev_and_sb(loop1)
   btrfs_fill_super
    open_ctree
     btrfs_free_extra_devids
      if (btrfs_device_1->bdev_file)
       fput(btrfs_device_1->bdev_file) // UAF !

Fix it by setting 'device->bdev_file' as 'NULL' after closing the
btrfs_device in btrfs_close_one_device().

Fixes: 142388194191 ("btrfs: do not background blkdev_put()")
CC: stable@vger.kernel.org # 4.19+
Link: https://bugzilla.kernel.org/show_bug.cgi?id=219408
Signed-off-by: Zhihao Cheng <chengzhihao1@huawei.com>
Reviewed-by: David Sterba <dsterba@suse.com>
Signed-off-by: David Sterba <dsterba@suse.com>

## Buggy Code

```c
// fs/btrfs/volumes.c
static void btrfs_close_one_device(struct btrfs_device *device)
{
	struct btrfs_fs_devices *fs_devices = device->fs_devices;

	if (test_bit(BTRFS_DEV_STATE_WRITEABLE, &device->dev_state) &&
	    device->devid != BTRFS_DEV_REPLACE_DEVID) {
		list_del_init(&device->dev_alloc_list);
		fs_devices->rw_devices--;
	}

	if (device->devid == BTRFS_DEV_REPLACE_DEVID)
		clear_bit(BTRFS_DEV_STATE_REPLACE_TGT, &device->dev_state);

	if (test_bit(BTRFS_DEV_STATE_MISSING, &device->dev_state)) {
		clear_bit(BTRFS_DEV_STATE_MISSING, &device->dev_state);
		fs_devices->missing_devices--;
	}

	btrfs_close_bdev(device);
	if (device->bdev) {
		fs_devices->open_devices--;
		device->bdev = NULL;
	}
	clear_bit(BTRFS_DEV_STATE_WRITEABLE, &device->dev_state);
	btrfs_destroy_dev_zone_info(device);

	device->fs_info = NULL;
	atomic_set(&device->dev_stats_ccnt, 0);
	extent_io_tree_release(&device->alloc_state);

	/*
	 * Reset the flush error record. We might have a transient flush error
	 * in this mount, and if so we aborted the current transaction and set
	 * the fs to an error state, guaranteeing no super blocks can be further
	 * committed. However that error might be transient and if we unmount the
	 * filesystem and mount it again, we should allow the mount to succeed
	 * (btrfs_check_rw_degradable() should not fail) - if after mounting the
	 * filesystem again we still get flush errors, then we will again abort
	 * any transaction and set the error state, guaranteeing no commits of
	 * unsafe super blocks.
	 */
	device->last_flush_error = 0;

	/* Verify the device is back in a pristine state  */
	WARN_ON(test_bit(BTRFS_DEV_STATE_FLUSH_SENT, &device->dev_state));
	WARN_ON(test_bit(BTRFS_DEV_STATE_REPLACE_TGT, &device->dev_state));
	WARN_ON(!list_empty(&device->dev_alloc_list));
	WARN_ON(!list_empty(&device->post_commit_list));
}
```

## Bug Fix Patch

```diff
diff --git a/fs/btrfs/volumes.c b/fs/btrfs/volumes.c
index 8f340ad1d938..eb51b609190f 100644
--- a/fs/btrfs/volumes.c
+++ b/fs/btrfs/volumes.c
@@ -1105,6 +1105,7 @@ static void btrfs_close_one_device(struct btrfs_device *device)
 	if (device->bdev) {
 		fs_devices->open_devices--;
 		device->bdev = NULL;
+		device->bdev_file = NULL;
 	}
 	clear_bit(BTRFS_DEV_STATE_WRITEABLE, &device->dev_state);
 	btrfs_destroy_dev_zone_info(device);
```

