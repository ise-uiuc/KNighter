## Bug Pattern

A resource pointer is released (e.g., fput/close) but the struct field holding that pointer is not set to NULL. Later code uses a non-NULL check on that stale pointer as a liveness test and operates on it again (e.g., fput), causing a use-after-free/double-release.

Concretely: btrfs_device->bdev_file is fput() via btrfs_close_bdev(), but not nulled; later code sees bdev_file != NULL and fput()s it again, triggering UAF.
