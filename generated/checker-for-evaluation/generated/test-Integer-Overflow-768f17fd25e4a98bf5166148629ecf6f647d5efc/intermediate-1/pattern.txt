## Bug Pattern

Performing arithmetic shifts on values computed as 32-bit integers without first upcasting them to a 64-bit type. This can lead to integer overflow when the shift amount is large, so the left shift is performed in a narrower type than intended. Explicitly casting the operand to u64 before shifting (as done in the fix) prevents overflow and yields the correct 64-bit result.