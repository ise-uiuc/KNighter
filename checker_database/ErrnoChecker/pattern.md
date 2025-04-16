```
## Bug Pattern

The bug pattern is the misuse of the global "errno" variable by performing operations on it (reading or overwriting) without first checking whether its value is valid. This occurs when a function call that might change errno is made while the current state indicates that errno’s value has not been verified (i.e., not “checked”), leading either to reading an undefined errno value or overwriting it before the program had a chance to inspect it. In essence, the root cause is the lack of immediate error-checking of errno before any subsequent operation that may modify its state.
```