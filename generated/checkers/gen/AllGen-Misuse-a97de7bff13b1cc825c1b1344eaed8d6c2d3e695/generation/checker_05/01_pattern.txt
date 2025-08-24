## Bug Pattern

In a setsockopt handler, copying a fixed-size object from user space with copy_from_sockptr(..., sizeof(T)) without first validating that optlen is at least sizeof(T) (or otherwise enforcing the expected size). This allows callers to pass a shorter optlen, causing an out-of-bounds read during the copy. Correct pattern is to check optlen >= sizeof(T) or use a helper like bt_copy_from_sockptr(&dst, sizeof(dst), optval, optlen) that validates and copies safely.
