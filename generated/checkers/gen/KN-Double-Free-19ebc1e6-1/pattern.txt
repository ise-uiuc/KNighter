## Bug Pattern

Retry/replay loop with shared cleanup that frees a pointer without resetting it to NULL:

replay_again:
    ...
    // ptr not reinitialized here after previous cleanup
    if (early_error)
        goto out;
    ptr = kmalloc(...);
    if (!ptr)
        goto out;
    ...
out:
    kfree(ptr);              // frees ptr
    if (should_retry)
        goto replay_again;   // next iteration may hit 'out' before re-allocating ptr -> kfree(ptr) again

Root cause: A pointer freed in a common error/cleanup label is not reinitialized before a retry path jumps back, allowing a second kfree of the stale, already-freed pointer if an error occurs before reallocation.
