## Bug Pattern

Allocating memory with device-managed APIs (devm_kcalloc/devm_kmalloc) and then manually freeing the same pointer (directly via kfree or indirectly via helpers like pinctrl_utils_free_map) in error/cleanup paths. This mixes devm-managed lifetime with manual frees, causing a double free when devres later frees the already-freed pointer.

Example:
- ptr = devm_kcalloc(dev, ...);
- ... on error: pinctrl_utils_free_map(..., ptr, ...); // internally kfree(ptr)
- Later: devm cleanup frees ptr again -> double free.
