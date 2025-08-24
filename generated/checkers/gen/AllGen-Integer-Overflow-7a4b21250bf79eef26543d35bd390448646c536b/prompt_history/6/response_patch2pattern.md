## Bug Pattern

Relying on roundup_pow_of_two() to detect overflow by checking for a zero result when computing a power-of-two size on 32-bit architectures:

n_buckets = roundup_pow_of_two(max_entries);
if (!n_buckets) // attempt to detect overflow
    return -E2BIG;

On 32-bit, roundup_pow_of_two() can perform an overflowing left shift (UB) for inputs > 2^31, so the result is not reliably zero. The correct pattern is to pre-validate the input (e.g., max_entries > 1UL << 31) before calling roundup_pow_of_two() to avoid undefined behavior.
