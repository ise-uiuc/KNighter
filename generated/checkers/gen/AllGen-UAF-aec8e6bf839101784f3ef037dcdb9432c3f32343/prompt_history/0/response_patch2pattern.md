## Bug Pattern

A resource pointer (struct file* bdev_file) is released (fput/close) but not set to NULL in the owning structure. Later code uses a non-NULL check on this stale pointer to decide to release it again, leading to a use-after-free/double-fput. The root cause is failing to nullify a stored resource pointer after closing it, when other paths rely on NULL-ness to indicate validity.
