```
## Bug Pattern

The checker models functions that mix two different error‐reporting mechanisms—using both the function’s return value and the global errno variable—in an inconsistent way. In these functions, one branch may signal success (with an expected “unused” or undefined errno), while one or more failure branches set errno (either to a fixed value, a range, or a state that must be checked). The bug pattern is that callers may mistakenly assume errno holds a valid error code regardless of the function’s return value, leading to improper error handling. This pattern appears when error reporting is split between a return value and a side‐effect on errno without clear, consistent rules for when errno is reliable, making it easy to misuse the function and ignore necessary checks.
```