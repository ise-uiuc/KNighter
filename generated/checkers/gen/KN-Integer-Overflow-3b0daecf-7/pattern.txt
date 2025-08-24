## Bug Pattern

Allocating an array with kmalloc/kzalloc by manually multiplying element size and count, e.g.:

pa = kzalloc(sizeof(struct elem) * n, GFP_KERNEL);

This manual size calculation can overflow (especially when n is user-controlled), resulting in an undersized allocation and potential out-of-bounds writes. The correct pattern is to use kcalloc(n, sizeof(struct elem), GFP_KERNEL), which performs overflow-checked multiplication.
