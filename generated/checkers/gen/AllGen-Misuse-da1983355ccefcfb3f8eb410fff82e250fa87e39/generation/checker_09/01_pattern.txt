## Bug Pattern

Writing into a flexible array member annotated with __counted_by() before initializing its count field.

Pattern example:
- Struct has: T arr[] __counted_by(n); with size tracked by n.
- Allocation uses struct_size() and kzalloc/kmalloc.
- Code copies into arr (e.g., memcpy) before setting n:

tz = kzalloc(struct_size(tz, trips, num_trips), GFP_KERNEL);
memcpy(tz->trips, trips, num_trips * sizeof(*trips));  // BUG: n is still 0
tz->num_trips = num_trips;

With FORTIFY_SOURCE and __counted_by, the destination buffer is seen as size 0 until n is set, causing a fortify overflow. The fix is to assign the count field before any writes to the flexible array.
