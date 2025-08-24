## Bug Pattern

Writing to a flexible-array member that is annotated with __counted_by(len_field) before initializing/updating its length field. Because kzalloc() zeros the struct, the len_field is 0 at first access, so CONFIG_FORTIFY_SOURCE/UBSAN_BOUNDS treat the flexible array as size 0 and flag memcpy()/memset() into it as an overflow.

Example:
struct S { u32 len; u8 data[] __counted_by(len); };

s = kzalloc(struct_size(s, data, n), GFP_KERNEL);
/* BUG: len not set yet; bounds check sees data size 0 */
memcpy(s->data, src, n);
s->len = n;  /* must be set before accessing s->data */
