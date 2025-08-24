## Bug Pattern

Publishing an object to a user-visible ID registry (e.g., inserting into an IDR/XArray via xa_alloc) before the object is fully initialized and protected by all required references. This premature registration makes the object accessible to other ioctls which can look it up (or even guess the ID) and destroy/free it while the creator still uses it, leading to a use-after-free race.

Typical code shape:
- xa_alloc()/idr_alloc() is called before:
  - final initialization steps, and/or
  - acquiring necessary refcounts (e.g., binding to the file/context).
- Another path (e.g., a “destroy” ioctl) can find the object by ID and free it concurrently.

Fix pattern:
- Complete initialization and take all required references first.
- Make the ID allocation/registration (xa_alloc/idr_alloc) the last step before returning to user space.
