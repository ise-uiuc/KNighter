## Bug Pattern

Relying on roundup_pow_of_two() to signal overflow by checking if its result is 0, when the input can exceed the largest representable power-of-two on 32-bit systems. On 32-bit arches, roundup_pow_of_two() (often implemented via 1UL << order) can perform a left shift by BITS_PER_LONG bits, which is undefined behavior. Thus, the post-call zero check is unreliable. The correct pattern is to pre-validate the input (e.g., x > 1UL << (BITS_PER_LONG - 1)) before calling roundup_pow_of_two().
