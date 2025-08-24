## Bug Pattern

A retry loop using a goto back to a label shares a common cleanup path that frees resources, but pointer variables freed in the cleanup are not reset to NULL at the start of each retry iteration. If an error occurs before the pointer is reallocated on a subsequent iteration, the cleanup path is taken again and kfree() is called on the stale (already freed) pointer, causing a double free.

Typical shape:
replay_again:
    /* state not reinitialized */
    if (error_before_alloc)
        goto out;     /* cleanup */

    ptr = kmalloc(...);
    ...
out:
    kfree(ptr);       /* frees ptr from prior try too */
    if (should_retry)
        goto replay_again;

Fix: set ptr = NULL at the start of each retry iteration (near the label) before any path can jump to the cleanup.
