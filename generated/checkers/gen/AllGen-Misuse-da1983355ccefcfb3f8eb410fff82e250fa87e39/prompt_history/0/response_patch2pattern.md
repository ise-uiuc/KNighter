## Bug Pattern

Writing to a flexible array member annotated with __counted_by(count) before initializing its count field.

Example:
struct S {
	int n;
	struct T arr[] __counted_by(n);
};

s = kzalloc(struct_size(s, arr, n), GFP_KERNEL);
/* BUG: n not yet set; FORTIFY sees arr size as 0 */
memcpy(s->arr, src, n * sizeof(*src));
s->n = n;

The count field (e.g., tz->num_trips) must be set before any memcpy/memset/memmove into the __counted_by array (e.g., tz->trips), otherwise FORTIFY treats the destination size as zero and triggers a buffer overflow check failure.
