```
## Bug Pattern

The bug pattern is the unsafe combination of memory protection flags that permit a memory region to be both writable and executable. In other words, if a call to mmap or mprotect sets the protection parameter such that both PROT_WRITE and PROT_EXEC are enabled, the memory region becomes susceptible to attacks because it can be modified and then executed, violating the W^X security policy.
```