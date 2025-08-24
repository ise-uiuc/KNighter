## Bug Pattern

Accessing a flexible-array member annotated with __counted_by(counter) before initializing its counter.

Example:
struct S { size_t len; u8 data[] __counted_by(len); };

S *s = kzalloc(struct_size(s, data, n), GFP_KERNEL);
/* BUG: counter is still 0 (from kzalloc) */
memcpy(s->data, src, n);  /* FORTIFY/UBSAN sees data as size 0 */
s->len = n;

Root cause: The length field used for run-time bounds checking is updated after the first use of the flexible array, causing FORTIFY_SOURCE/UBSAN to treat the array as zero-sized and report/trigger an overflow.
