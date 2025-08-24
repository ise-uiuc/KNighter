## Bug Pattern

Manually computing the allocation size for an array as count * element_size when calling kmalloc/kzalloc, where count can be large or user-controlled, leading to integer overflow and under-allocation. Subsequent writes using the intended count then overrun the allocated buffer. Correct approach is to use kcalloc/kvcalloc(count, element_size, GFP_KERNEL), which performs overflow-checked multiplication.
