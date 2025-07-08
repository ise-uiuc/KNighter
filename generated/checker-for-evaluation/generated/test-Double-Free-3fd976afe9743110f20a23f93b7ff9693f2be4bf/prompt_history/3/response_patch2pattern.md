## Bug Pattern

Using a device-managed allocation function (like devm_kcalloc) for memory that is later manually freed, leading to a double free. This happens because the memory is automatically released during device removal and then freed again by an explicit free routine (dt_free_map), resulting in double freeing of the allocated resource.