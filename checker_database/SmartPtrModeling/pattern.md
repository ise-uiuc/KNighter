```
## Bug Pattern

The bug pattern is the unchecked use (or dereference) of a smart pointer whose internal raw pointer value may be null. This situation arises from operations such as default construction, release, reset, swap, assignment, or move‑construction—actions that may leave the smart pointer in a “moved-from” or otherwise null state. If the code later uses the smart pointer (for example via operator bool, get, or comparisons) without verifying that its underlying pointer is non-null, it risks dereferencing a null pointer, leading to invalid memory access and undefined behavior.
```