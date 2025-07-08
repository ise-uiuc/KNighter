## Bug Pattern

Initializing a field used by fortified memory functions (via __counted_by annotations) only after a memory copy operation. In this case, the trip count (num_trips) that determines the expected size of the trips buffer is assigned after memcpy(), causing the fortify checks to treat the buffer size as zero and flag a buffer overflow, leading to a kernel panic.