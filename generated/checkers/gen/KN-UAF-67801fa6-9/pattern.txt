## Bug Pattern

Publishing a newly created object into a user-visible ID registry (e.g., xarray/idr via xa_alloc/idr_alloc) before the object is fully initialized and all required references are taken. Specifically:
- Calling xa_alloc(&xa, &id, obj, ...) before completing initialization (e.g., setting obj->refs/owner fields) or before the create path stops using obj.
- This makes the object accessible to other ioctls which can look it up by ID and destroy/free it while the create ioctl still references or initializes it, leading to a use-after-free.

Correct pattern: finish all object initialization and take needed references first, then perform the ID allocation/publication as the last step.
