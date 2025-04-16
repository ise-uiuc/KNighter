```
## Bug Pattern

Casting a pointer to a structure type when the original pointer does not refer to a structure, or converting between structure pointers where the target structure is wider than the original. This pattern leads to potential memory access errors or data corruption because fields may be accessed beyond the actual storage layout of the original data.
```