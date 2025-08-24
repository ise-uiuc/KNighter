## Bug Pattern

Relying on roundup_pow_of_two(x) to detect overflow after the fact:

```
n = roundup_pow_of_two(x);   // x may require 2^BITS_PER_LONG or larger
if (!n)                      // assume overflow => 0
    return -E2BIG;
```

On 32-bit arches, roundup_pow_of_two() can perform a left shift by 32 (or more), which is undefined behavior. Thus the “result == 0” check is not reliable and may not catch the overflow. The correct pattern is to pre-validate x against the maximum safe input before calling roundup_pow_of_two():

```
if (x > (1UL << (BITS_PER_LONG - 1)))
    return -E2BIG;
n = roundup_pow_of_two(x);
```
