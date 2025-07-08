```
## Bug Pattern

Allocating an array by manually multiplying the element size by a count (which can be influenced by user input) without checking for integer overflow. This unsafe multiplication can overflow, resulting in an allocation that is too small and subsequently leading to buffer overflows or memory corruption. Using a safe allocation function like kcalloc prevents this overflow by internally performing the multiplication with overflow checks.
```