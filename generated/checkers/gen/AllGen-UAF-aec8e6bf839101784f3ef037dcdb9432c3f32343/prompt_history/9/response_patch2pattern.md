## Bug Pattern

Leaving a stale struct file* pointer in a persistent structure after the resource has been released (e.g., via fput()/close in a helper like btrfs_close_bdev()), and later using a non-NULL check on that pointer to perform another put/close. In short: a pointer field is freed by a callee but not set to NULL, so subsequent cleanup paths treat the dangling non-NULL pointer as valid and dereference it, causing a use-after-free/double fput.
