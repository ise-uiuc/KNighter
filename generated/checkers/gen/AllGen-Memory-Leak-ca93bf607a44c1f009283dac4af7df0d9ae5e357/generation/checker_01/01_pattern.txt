## Bug Pattern

Allocating a temporary (non-devm) buffer and intending to free it later, but returning early on a subsequent allocation failure without freeing the temporary buffer. Concretely: memory obtained (e.g., via nvmem_cell_read/kmalloc) is freed only on the success path; if a later devm_krealloc (or similar) fails, the function returns without kfree() of the earlier buffer, causing a leak.
