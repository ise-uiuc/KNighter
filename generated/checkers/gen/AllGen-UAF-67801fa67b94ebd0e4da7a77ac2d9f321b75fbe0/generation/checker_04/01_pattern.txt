## Bug Pattern

Publishing a newly created object to a user-visible ID registry (e.g., xa_alloc/idr_alloc) before the object is fully initialized and before the create ioctl completes. This early registration makes the object discoverable (often with a predictable/guessable ID), allowing a concurrent destroy ioctl to free it while the create path still uses it, leading to a use-after-free. The fix is to defer inserting into the ID map until the last step of the ioctl, after taking needed references and completing initialization.
