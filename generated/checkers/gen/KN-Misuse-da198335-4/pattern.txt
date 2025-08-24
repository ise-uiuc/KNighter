## Bug Pattern

Copying into a flexible-array member that is annotated with __counted_by(count) before initializing the associated count field. Specifically:
- A struct contains `T arr[] __counted_by(n);`
- The instance is kzalloc’d (so `n == 0`)
- A fortified function (e.g., memcpy) writes to `arr` before `obj->n` is set

With CONFIG_FORTIFY_SOURCE and __counted_by, the object size for `arr` is computed from `obj->n`, which is still 0, so any write is seen as a buffer overflow. The count field must be set before any access/copy into the flexible array.
