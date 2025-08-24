## Bug Pattern

Copying into a flexible-array member annotated with __counted_by(count) before initializing the associated count field. With CONFIG_FORTIFY_SOURCE, the buffer size of the destination is derived from the (zero-initialized) count field (due to kzalloc), so calling memcpy/memset/etc. on the flexible array before setting count causes FORTIFY to see a zero-sized destination and report an overflow.
