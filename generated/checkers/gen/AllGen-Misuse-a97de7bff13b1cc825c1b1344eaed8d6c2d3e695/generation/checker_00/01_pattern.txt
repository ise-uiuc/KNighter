## Bug Pattern

In a setsockopt handler, copying option data with a fixed-size read (e.g., copy_from_sockptr(&dst, optval, sizeof(dst))) without validating that the user-supplied optlen is at least that size. This can over-read the caller’s buffer (slab-out-of-bounds) when optlen is smaller. Correct code must check optlen >= expected_size or use a helper that enforces this (e.g., bt_copy_from_sockptr(&dst, sizeof(dst), optval, optlen)).
