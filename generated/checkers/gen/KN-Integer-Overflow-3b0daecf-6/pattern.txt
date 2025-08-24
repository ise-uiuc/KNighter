## Bug Pattern

Allocating an array with kmalloc/kzalloc using manual multiplication of count and element size without overflow checking:

p = kzalloc(n * sizeof(*p), GFP_KERNEL);

If n is large (potentially user-controlled), n * sizeof(*p) can overflow size_t, leading to an undersized allocation and subsequent out-of-bounds writes. The correct pattern is to use kcalloc(n, sizeof(*p), GFP_KERNEL), which detects overflow.
