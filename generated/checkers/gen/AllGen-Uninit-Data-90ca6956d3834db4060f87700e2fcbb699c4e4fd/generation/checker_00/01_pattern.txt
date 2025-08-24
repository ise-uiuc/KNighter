## Bug Pattern

Using auto-cleanup pointers (e.g., `type *p __free(kfree);`) without initializing them to NULL, while having early returns/gotos before the pointer is assigned. On scope exit, the cleanup will call `kfree()` on an uninitialized (garbage) pointer.

Example:
type *p __free(kfree);
if (err)
    return -EINVAL;  // triggers kfree(p) on uninitialized p

Fix: Initialize all `__free(kfree)` pointers to NULL at declaration:
type *p __free(kfree) = NULL;
