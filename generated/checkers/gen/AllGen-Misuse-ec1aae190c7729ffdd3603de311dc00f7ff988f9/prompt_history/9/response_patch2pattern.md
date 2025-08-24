## Bug Pattern

Accessing (e.g., memcpy to) a flexible-array member annotated with __counted_by(counter) before initializing its counter field.

Example:
- struct S { u32 len; u8 data[] __counted_by(len); };
- s = kzalloc(struct_size(s, data, n), GFP_KERNEL);
- memcpy(s->data, src, n);        // BUG: s->len is still 0
- s->len = n;

Because kzalloc() zeroes the counter, FORTIFY/UBSAN use len==0 for bounds, so the first access to data[] is seen as an overflow. The counter must be set before any read/write of the flexible array:
- s->len = n;
- memcpy(s->data, src, n);
