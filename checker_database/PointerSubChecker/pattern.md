```
## Bug Pattern

Subtracting two pointers that refer to different underlying memory regions (i.e., not from the same memory chunk) can lead to undefined behavior or incorrect results. This bug pattern arises when pointer arithmetic is performed on pointers derived from distinct allocations or non-overlapping memory buffers, a situation that should be detected and warned against.
```