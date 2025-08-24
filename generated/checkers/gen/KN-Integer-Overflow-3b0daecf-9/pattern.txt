## Bug Pattern

Allocating an array with kmalloc/kzalloc using manual multiplication (e.g., kzalloc(sizeof(elem) * n, GFP_KERNEL)) without overflow checking. If n is large or user-controlled, the size multiplication can overflow, causing an undersized allocation and subsequent out-of-bounds writes when filling n elements. The correct pattern is to use array allocators (kcalloc/kmalloc_array) which perform overflow checking.
