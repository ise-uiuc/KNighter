## Bug Pattern

Using a device-managed memory allocation (devm_kcalloc) for a data structure that is later freed manually (via dt_free_map calling pinctrl_utils_free_map) leads to a double free. The bug arises from mixing automatic (devm_*) memory management with manual memory deallocation, causing the same memory to be freed twice.