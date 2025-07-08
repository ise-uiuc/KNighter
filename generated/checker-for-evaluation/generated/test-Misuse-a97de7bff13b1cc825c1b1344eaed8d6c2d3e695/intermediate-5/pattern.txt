```
## Bug Pattern

Failure to validate that the user-supplied length (optlen) is sufficient before copying data from userspace. In the original code, copy_from_sockptr() is used without ensuring that optlen is at least as large as the destination buffer size, potentially causing out-of-bounds memory accesses. The patch fixes this by using bt_copy_from_sockptr(), which checks the actual input length against the expected size, thus preventing invalid memory accesses.
```