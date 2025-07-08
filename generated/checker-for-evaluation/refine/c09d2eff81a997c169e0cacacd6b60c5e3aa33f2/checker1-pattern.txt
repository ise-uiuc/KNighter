## Bug Pattern

Performing arithmetic on 32-bit values that may overflow before assigning the result to a 64-bit variable. In other words, multiplying two 32-bit integers without casting one operand to a 64-bit type first, which causes an unintentional integer overflow in 32-bit arithmetic prior to storing the result in a larger (64-bit) context.