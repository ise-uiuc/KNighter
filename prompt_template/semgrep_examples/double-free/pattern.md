## Bug Pattern

The bug pattern is **double-free vulnerability caused by mixing device-managed memory allocation with manual deallocation**. 

The issue occurs when:
1. Memory is allocated using device-managed allocation functions (`devm_kcalloc`, `devm_kmalloc`, etc.)
2. The same memory is later manually freed using functions like `kfree`, `kvfree`, or `pinctrl_utils_free_map`

Device-managed allocations are automatically freed when the device is removed or the driver is unloaded. Manual deallocation of such memory leads to a double-free condition, which can cause:
- Memory corruption
- System crashes
- Security vulnerabilities
- Undefined behavior

The pattern specifically involves:
- Using `devm_*` allocation functions for memory management
- Having error paths or cleanup code that manually calls free functions
- The manual free functions operating on pointers that were allocated with `devm_*`
