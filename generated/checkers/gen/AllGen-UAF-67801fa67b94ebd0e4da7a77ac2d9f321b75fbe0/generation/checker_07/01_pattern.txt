## Bug Pattern

Publishing a newly created kernel object into a globally accessible ID map (e.g., xarray/IDR via xa_alloc/idr_alloc) before the object is fully initialized and before all necessary references are established. This makes the object visible to other ioctls which can lookup and destroy it, causing a race where the creator continues to use a now-freed pointer (use-after-free). The telltale code shape is:

q = alloc_object();
... partial init ...
xa_alloc(table, &id, q, ...);  // publishes object too early
... further init / reference setup on q ...
// concurrent destroy by id can free q -> UAF on further init lines

Fix: complete initialization and take required references first; make the ID insertion the last step before returning.
