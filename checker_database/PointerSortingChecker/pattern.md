```
## Bug Pattern

Using standard sorting algorithms (e.g. std::sort, std::stable_sort, etc.) on containers holding pointer-like elements can lead to non-deterministic orderings. This is because the sort is based on the memory addresses of the pointers rather than on the values they point to, which may vary between runs, resulting in inconsistent or unpredictable ordering.
```