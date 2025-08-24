## Bug Pattern

Allocating a temporary buffer and then returning early on a subsequent allocation/reallocation failure without freeing the temporary buffer, causing a leak. Concretely:

- A temporary buffer is allocated (e.g., via nvmem_cell_read()).
- A reallocation of the destination buffer is attempted (e.g., devm_krealloc()).
- On failure of the reallocation, the code returns without kfree() of the temporary buffer.

Example:

u8 *tmp = nvmem_cell_read(cell, &len);  // must be kfree'd
...
dst = devm_krealloc(dev, dst, new_len, GFP_KERNEL);
if (!dst)
    return -ENOMEM;  // missing kfree(tmp) -> memory leak
