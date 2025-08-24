## Bug Pattern

Writing to a flexible-array member annotated with __counted_by(len_field) before initializing its length field.

Typical form:
- A struct has: u32 len; u8 data[] __counted_by(len);
- The object is zero-initialized (e.g., via kzalloc), so len starts at 0.
- Code allocates with struct_size(..., len), but then does memcpy(obj->data, src, len) before setting obj->len = len.
- Because len is still 0, FORTIFY/UBSAN bounds checks see data as size 0 and flag a buffer overflow.

Correct sequence is to set the counter (len_field) before any access to the flexible array.
