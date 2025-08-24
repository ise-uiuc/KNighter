## Bug Pattern

Manually multiplying count by element size when allocating an array with kmalloc/kzalloc:
ptr = kzalloc(count * sizeof(*ptr), GFP_KERNEL);
This risks integer overflow in the size calculation, leading to undersized allocations and subsequent out-of-bounds writes/reads. Use kcalloc(count, sizeof(*ptr), GFP_KERNEL) which performs overflow checking.
