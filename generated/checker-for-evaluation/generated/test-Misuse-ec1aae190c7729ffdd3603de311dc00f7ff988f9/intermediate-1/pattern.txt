```
## Bug Pattern

The bug pattern is updating the size counter for a flexible-array member (i.e. the field annotated with __counted_by) after the first access to that flexible array. In this case, copying data into a flexible-array member is performed before updating its associated counter (datalen), causing runtime bounds-checking (enabled by CONFIG_FORTIFY_SOURCE and CONFIG_UBSAN_BOUNDS) to operate on an incorrect (zero) size. This misordering can trigger a buffer overflow check failure, as the bounds verifications mistakenly treat the memcpy operation as writing beyond the valid memory bounds.
```