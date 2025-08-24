## Bug Pattern

Allocating a variable-length array with kmalloc/kzalloc by manually multiplying element count and size (n * sizeof(T)) without overflow checking. If n is large, the multiplication can overflow, leading to an undersized allocation and subsequent out-of-bounds writes. Use kcalloc() or kmalloc_array() which perform overflow-checked size calculations.
