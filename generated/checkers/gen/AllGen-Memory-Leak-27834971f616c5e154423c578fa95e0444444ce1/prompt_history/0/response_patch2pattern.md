## Bug Pattern

Freeing pages after a failed set_memory_decrypted() (or similar memory attribute transition) under the assumption that failure means “no state change.”

Example:
```
addr = alloc_pages_exact(len, GFP_KERNEL|__GFP_ZERO);
if (set_memory_decrypted((unsigned long)addr, count)) {
    free_pages_exact(addr, len);  // BUG: may return decrypted/shared pages to allocator
    return NULL;
}
```

In CoCo guests, set_memory_decrypted() can fail while leaving pages decrypted/shared. Returning such pages to the allocator can cause security/functional issues. The correct handling is to leak/quarantine the pages on failure, not free them.
