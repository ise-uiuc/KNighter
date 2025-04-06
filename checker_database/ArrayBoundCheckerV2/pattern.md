```
## Bug Pattern

Accessing an array or memory block using an index or offset that is computed via symbolic arithmetic and not properly constrained within the bounds (either below zero or beyond the block’s extent). In particular, the bug pattern occurs when the computed offset from an array subscripting or pointer dereference is not validated against the actual size of the underlying memory region—potentially allowing negative (underflow) or excessive (overflow) offsets, and even when the offset is tainted. This unchecked arithmetic can lead to out‐of‐bounds memory accesses.
```