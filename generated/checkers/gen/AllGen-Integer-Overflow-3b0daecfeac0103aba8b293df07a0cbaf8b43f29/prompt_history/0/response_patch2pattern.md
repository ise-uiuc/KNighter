## Bug Pattern

Allocating an array with kmalloc/kzalloc using manual size multiplication without overflow checking:

- Pattern: buf = kzalloc(sizeof(struct item) * count, GFP_KERNEL);
- Problem: If count is large or user-controlled, the multiplication can overflow, allocating too small a buffer and leading to memory corruption when writing count elements.
- Fix: Use kcalloc(count, sizeof(struct item), GFP_KERNEL) (or array_size/struct_size helpers), which performs overflow-checked size calculations.
