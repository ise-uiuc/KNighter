## Bug Pattern

Reading a fixed-size integer/struct from setsockopt’s optval with:
copy_from_sockptr(&obj, optval, sizeof(obj))
without first validating that optlen is at least sizeof(obj) (or without clamping to optlen and zero-initializing the remainder). This allows slab/out-of-bounds reads when optlen is smaller than expected (notably for KERNEL_SOCKPTR sources), and can also leave partially initialized structs.
