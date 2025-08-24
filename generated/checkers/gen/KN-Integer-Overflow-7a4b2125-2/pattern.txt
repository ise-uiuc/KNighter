## Bug Pattern

Relying on roundup_pow_of_two(x) for overflow detection by checking if the result is zero, instead of validating x beforehand. On 32-bit architectures, roundup_pow_of_two() can perform a left shift by the word size (e.g., 1UL << 32) when x is too large, which is undefined behavior. Thus, the overflow check must be done before calling roundup_pow_of_two() (e.g., reject x > 1UL << 31) rather than checking the rounded result.
