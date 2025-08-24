## Bug Pattern

Leaving a stale pointer after releasing a resource: a field (device->bdev_file) is freed/closed (via btrfs_close_bdev/fput) but not set to NULL. Later cleanup code uses a non-NULL check (if (device->bdev_file) fput(device->bdev_file)) to release again, causing a use-after-free. The pattern is “not nullifying a struct member pointer after close/free, then reusing it based on non-NULL tests,” leading to double-release/UAF.
