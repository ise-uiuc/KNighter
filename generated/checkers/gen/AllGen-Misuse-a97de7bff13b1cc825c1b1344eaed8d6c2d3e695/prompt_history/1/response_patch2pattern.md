## Bug Pattern

In a setsockopt handler, copying a fixed-size value/struct from optval using copy_from_sockptr (or similar) without validating that the user-supplied optlen is at least the required size (or using a helper that enforces this). Sometimes this appears as copying min(sizeof(dst), optlen) bytes into dst, leaving parts of dst uninitialized. This can cause slab-out-of-bounds reads or use of uninitialized fields.
