## Bug Pattern

Publishing a newly created object to a globally visible ID store (xarray/idr via xa_alloc/idr_alloc) before the create path is fully finalized and ownership/refcounting is established. Because the ID is predictable, another thread can issue a destroy/lookup by that ID while the creator still holds only a raw pointer or the object is partially initialized, leading to a race and use-after-free. The correct pattern is to defer ID allocation/registration until the very end of the ioctl, after all initialization and reference ownership (e.g., q->xef = xe_file_get(xef)) is set.
