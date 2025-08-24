## Bug Pattern

Publishing a newly created kernel object to a user-visible ID registry (e.g., xarray/IDR via xa_alloc/idr_alloc) before the object is fully initialized and before taking a protecting reference from its owner. Because the assigned ID is predictable, another ioctl can race to destroy the object by that ID while the create ioctl still uses it, leading to a use-after-free. The fix is to complete initialization and acquire all necessary references first, and only then perform the ID allocation/registration as the final step.
