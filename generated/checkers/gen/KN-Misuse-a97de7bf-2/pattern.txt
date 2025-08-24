## Bug Pattern

Calling copy_from_sockptr() with a fixed size for the destination object without validating that optlen is at least that size (or otherwise bounding the copy by optlen), e.g.:

- if (copy_from_sockptr(&opt, optval, sizeof(opt))) …
- if (copy_from_sockptr(&sec, optval, sizeof(sec))) …

This ignores the user-provided optlen and can:
- overread when optval is a KERNEL_SOCKPTR to a smaller slab object (slab-out-of-bounds), or
- result in partially initialized structures if optlen is shorter than expected.

Correct pattern: check optlen >= sizeof(obj) or use a helper that validates/bounds the copy (e.g., bt_copy_from_sockptr(&obj, sizeof(obj), optval, optlen)).
