## Bug Pattern

Writing to a flexible-array member annotated with __counted_by(counter) before initializing its counter field.

Example:
struct obj {
    size_t len;
    u8 data[] __counted_by(len);
};

obj = kzalloc(struct_size(obj, data, n), GFP_KERNEL);
/* BUG: len is 0 here due to kzalloc, so FORTIFY/UBSAN see data size as 0 */
memcpy(obj->data, src, n);
obj->len = n;

Accesses to data must occur only after setting obj->len = n; otherwise, runtime bounds checks (FORTIFY_SOURCE/UBSAN_BOUNDS) treat the destination size as zero, flagging an overflow and potentially crashing.
