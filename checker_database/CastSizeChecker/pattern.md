## Bug Pattern

Casting a pointer to a memory region whose actual allocated size isn’t a multiple of the destination type’s size. This mismatch indicates that the allocated memory may not correctly accommodate an array of the destination type, potentially leading to misaligned accesses, buffer overruns, or unintended behavior—especially when handling structures with flexible array members.