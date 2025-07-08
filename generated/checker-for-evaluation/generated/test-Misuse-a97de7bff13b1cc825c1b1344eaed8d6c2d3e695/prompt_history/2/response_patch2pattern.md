```
## Bug Pattern

Failure to validate that the user-supplied buffer length is sufficient before copying data from user space. The original code uses copy_from_sockptr() without checking that the provided optlen is at least the size of the object to be copied, which can lead to out-of-bounds memory accesses. This pattern—using copy operations without adequate verification of the user input length—can expose the system to memory corruption and potential security vulnerabilities.
```