## Bug Pattern

Resource pointer not cleared after being released: a member pointer (e.g., device->bdev_file) is freed/put by a close/release routine but left non-NULL, and later cleanup code uses a truthy pointer check to perform another put/free, causing use-after-free.

Example:
- close_fn(obj):
    fput(obj->file);  // releases file
    // obj->file still holds stale non-NULL pointer
- later:
    if (obj->file)
        fput(obj->file);  // UAF/double-put

Correct pattern is to set the pointer to NULL immediately after releasing it to prevent subsequent conditional frees from using a dangling pointer.
