## Bug Pattern

Writing to a flexible array member annotated with __counted_by(size_field) before initializing the corresponding size_field. Because the object was zero-initialized (e.g., via kzalloc), the fortify bounds checks see the flexible array’s size as 0 and flag any memcpy/write as an overflow.

Example pattern:
struct S {
	int n;
	struct T arr[] __counted_by(n);
};

s = kzalloc(struct_size(s, arr, n), GFP_KERNEL);
/* BUG: n not set yet; arr is seen as size 0 by FORTIFY */
memcpy(s->arr, src, n * sizeof(*src));
s->n = n;  /* should be set before accessing arr */
