## Bug Pattern

In setsockopt handlers, copying a fixed-size value/struct from user space without validating the provided optlen:

- Using copy_from_sockptr(dst, optval, sizeof(dst_type)) when optlen < sizeof(dst_type), causing out-of-bounds reads.
- Or copying only min(optlen, sizeof(struct)) and then reading struct fields, leading to use of uninitialized data.

Root cause: not ensuring optlen >= expected size (or not using a helper that enforces this) before copying and accessing the data.
