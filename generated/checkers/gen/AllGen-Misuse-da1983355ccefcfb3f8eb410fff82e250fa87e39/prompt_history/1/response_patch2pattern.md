## Bug Pattern

Copying into a flexible-array member annotated with __counted_by(field) before initializing the counting field. Because the struct is zero-initialized (kzalloc), the count field is 0 when memcpy() (or similar) is called, so FORTIFY computes the destination size as 0 and reports an overflow. The correct order is to set the count field first, then access/copy into the counted flexible array.
