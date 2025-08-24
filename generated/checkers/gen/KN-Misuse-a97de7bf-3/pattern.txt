## Bug Pattern

Using copy_from_sockptr() (or similar) with a fixed sizeof(type) in a setsockopt handler without validating the provided optlen, leading to reads beyond the caller-provided buffer (especially when sockptr is a kernel pointer).

Anti-pattern:
- copy_from_sockptr(&obj, optval, sizeof(obj));  // no optlen check

Correct pattern:
- if (optlen != sizeof(obj)) return -EINVAL;
- or use a helper that enforces/validates optlen, e.g. bt_copy_from_sockptr(&obj, sizeof(obj), optval, optlen)

This missing optlen validation can cause slab-out-of-bounds reads or partial/unchecked struct copies.
