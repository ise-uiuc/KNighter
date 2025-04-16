```
## Bug Pattern

The checker identifies cases where a divisor is used in a division (or related modulo operation) without first confirming that it is non-zero, and then later the same value is compared against zero in a branch condition. In essence, the bug pattern is “testing a divisor for zero after it has already been used in a division operation,” meaning the safety check comes too late to prevent a division-by-zero error.
```