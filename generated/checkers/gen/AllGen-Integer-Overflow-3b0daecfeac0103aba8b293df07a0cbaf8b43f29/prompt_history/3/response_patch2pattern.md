## Bug Pattern

Allocating an array with kmalloc/kzalloc using manual multiplication of element size and count without overflow checking, where the count may come from user input:

ptr = kzalloc(sizeof(struct elem) * n, GFP_KERNEL);
/* ... later use ptr[i] for i in [0, n) ... */

This multiplication can overflow size_t, leading to an under-sized allocation and subsequent out-of-bounds writes when populating the array. Use kcalloc(n, sizeof(struct elem), GFP_KERNEL) (or explicit overflow-checked helpers) to prevent integer overflow.
