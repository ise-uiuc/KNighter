## Bug Pattern

Copying into a flexible array member that is annotated with __counted_by(size_field) before initializing the size_field. Because the struct is zero-initialized (kzalloc), the size_field is 0 at the time of memcpy, so FORTIFY_SOURCE sees a zero-sized destination and reports a buffer overflow.

Example pattern:
- struct S { int n; T arr[] __counted_by(n); };
- s = kzalloc(struct_size(S, arr, n), ...);
- memcpy(s->arr, src, n * sizeof(T));  // BUG: s->n is still 0
- s->n = n;

Correct order:
- s->n = n;
- memcpy(s->arr, src, n * sizeof(T));
