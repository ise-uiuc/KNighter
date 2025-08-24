## Bug Pattern

Using roundup_pow_of_two(x) on unbounded input and detecting overflow by testing the rounded result for zero:

```
n = roundup_pow_of_two(x);
if (!n)
    /* assume overflow */
```

On 32-bit architectures, roundup_pow_of_two() can perform a 32-bit left shift by ≥ 32, invoking undefined behavior. This makes the post-rounding check (n == 0) unreliable. The correct approach is to validate x (e.g., x > 1UL << 31) before calling roundup_pow_of_two().
