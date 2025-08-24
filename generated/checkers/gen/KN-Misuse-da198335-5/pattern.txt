## Bug Pattern

Writing to a flexible array member annotated with __counted_by(count) before initializing the controlling count field. Specifically:

- Object is kzalloc’d, so count starts at 0.
- A memcpy (or similar write) to the __counted_by array is performed before setting count.
- FORTIFY_SOURCE uses count to compute the destination size and sees zero, flagging a buffer overflow.

Example pattern:
struct S {
	size_t n;
	struct T arr[] __counted_by(n);
};

s = kzalloc(struct_size(s, arr, n), GFP_KERNEL);
/* BUG: n is still 0, FORTIFY sees arr size 0 */
memcpy(s->arr, src, n * sizeof(*src));
s->n = n;
