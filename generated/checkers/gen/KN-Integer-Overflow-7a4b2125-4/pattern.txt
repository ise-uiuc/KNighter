## Bug Pattern

Detecting overflow by checking the result of roundup_pow_of_two(x) for zero after the call, instead of validating x beforehand. On 32-bit architectures, roundup_pow_of_two() may perform a left shift by ≥32 (e.g., when x > 1UL << 31), which is undefined behavior, so the function can return a non-zero garbage value and the post-call zero check fails. The buggy idiom looks like:

n = roundup_pow_of_two(x);
if (!n)
    /* assume overflow */

Correct pattern: first ensure x <= (1UL << 31), then call roundup_pow_of_two().
