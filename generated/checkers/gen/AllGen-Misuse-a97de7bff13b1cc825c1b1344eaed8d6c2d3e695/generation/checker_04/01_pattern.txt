## Bug Pattern

Blindly copying a fixed-sized object from a sockptr in a setsockopt handler without validating the user-provided optlen.

Typical faulty pattern:
```
int err;
u32 opt;
...
/* No check that optlen >= sizeof(opt) */
if (copy_from_sockptr(&opt, optval, sizeof(opt)))
    return -EFAULT;
```

Safer pattern:
```
int err;
u32 opt;
...
if (optlen < sizeof(opt))
    return -EINVAL;
if (copy_from_sockptr(&opt, optval, sizeof(opt)))
    return -EFAULT;
```
or use a helper that enforces length checking:
```
if (bt_copy_from_sockptr(&opt, sizeof(opt), optval, optlen))
    return -EFAULT;
```

Root cause: not validating optlen before copying causes slab-out-of-bounds reads when the kernel-side buffer backing sockptr is only optlen bytes long.
