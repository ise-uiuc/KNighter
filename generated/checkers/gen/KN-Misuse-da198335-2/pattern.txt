## Bug Pattern

Copying into a flexible array member annotated with __counted_by(size_field) before initializing its size_field.

Example pattern:
- struct has: T elems[] __counted_by(n);
- object allocated with kzalloc/struct_size(..., elems, n);
- a memop (memcpy/memset/etc.) is performed on elems before setting obj->n.

Because kzalloc zeroes the object, n is 0 at the time of the memop, so FORTIFY_SOURCE uses a runtime size of 0 for elems and flags a buffer overflow. The size_field must be set before any operation that writes to the counted flexible array.
