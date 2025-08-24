## Bug Pattern

Allocating a temporary buffer (e.g., via nvmem_cell_read/kmalloc) and then performing a devm_krealloc on another pointer; if devm_krealloc fails, returning immediately without freeing the temporary buffer, causing a memory leak.

Example pattern:
- tmp = kmalloc(...);
- dst = devm_krealloc(dev, dst, new_size, GFP_KERNEL);
- if (!dst) return -ENOMEM;  // missing kfree(tmp) here

In this case: efuse (kmalloc’ed by nvmem_cell_read) is not freed when devm_krealloc for lvts_td->calib fails.
