## Bug Pattern

The bug pattern is the assignment of a fixed, hard-coded (non-zero constant) address to a pointer. This pattern is characterized by directly assigning a constant pointer value—which is not zero—to a pointer variable, leading to portability issues because the fixed address may not be valid in different environments or platforms.