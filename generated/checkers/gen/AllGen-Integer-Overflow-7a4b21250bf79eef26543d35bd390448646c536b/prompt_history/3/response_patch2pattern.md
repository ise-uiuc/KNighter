## Bug Pattern

Computing a power-of-two size with roundup_pow_of_two(x) on an unvalidated 32-bit unsigned long input and detecting overflow by checking the returned value (e.g., if (!n)).

On 32-bit arches, roundup_pow_of_two() internally does a left shift (1UL << k). For x > (1UL << 31), this implies a shift by 32 bits, which is undefined behavior. Relying on the result being 0 to detect overflow is non-portable and unsafe. The correct pattern is to pre-validate that x <= (1UL << 31) before calling roundup_pow_of_two(), avoiding the UB entirely.
