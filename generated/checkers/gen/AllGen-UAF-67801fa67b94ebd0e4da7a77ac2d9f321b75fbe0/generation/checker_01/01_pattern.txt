## Bug Pattern

Publishing a newly created object into a globally accessible ID registry (e.g., xarray/idr via xa_alloc) before the object is fully initialized and before the creating ioctl completes. Because the assigned ID is predictable/guessable, another thread can issue a destroy/lookup using that ID during the creation path, freeing the object while the creator still uses it, leading to a use-after-free.
