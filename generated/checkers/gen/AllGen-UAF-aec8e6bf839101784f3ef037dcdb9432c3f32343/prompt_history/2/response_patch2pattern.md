## Bug Pattern

Stale pointer after resource release: a struct file* (device->bdev_file) is fput()/closed but the field is left non-NULL. Later code uses a non-NULL check as an ownership indicator and calls fput() again, causing use-after-free/double-put. The pattern is failing to set a released resource pointer to NULL when other paths rely on pointer-nullness to decide whether to free/put it again.
