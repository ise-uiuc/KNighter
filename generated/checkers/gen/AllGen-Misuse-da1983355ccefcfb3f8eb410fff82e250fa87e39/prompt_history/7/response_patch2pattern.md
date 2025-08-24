## Bug Pattern

Writing into a flexible array member annotated with __counted_by(size_field) before initializing its size_field. Specifically:
- The object is kzalloc'ed, so the counted-by length field is zero.
- A memcpy (or similar write) to the flexible array occurs before setting the size_field.
- FORTIFY uses the zero size_field to compute the destination buffer size as 0, triggering a buffer overflow check.

Example pattern:
struct S { int n; struct T arr[] __counted_by(n); };
s = kzalloc(struct_size(s, arr, n), GFP_KERNEL);
memcpy(s->arr, src, n * sizeof(*src)); // BUG: s->n still 0
s->n = n;
