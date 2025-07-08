## Bug Pattern

Using device-managed memory allocation (devm_kcalloc) for resources that are later explicitly freed by other code paths leads to a double free. The allocation is automatically supposed to be freed on device removal, so combining it with manual deallocation (through functions like pinctrl_utils_free_map) can inadvertently free the same memory twice.