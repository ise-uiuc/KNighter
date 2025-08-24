## Bug Pattern

Concurrent access to a shared pointer field with inconsistent locking:
- One path reads and check-then-uses a pointer under spinlock L:
  spin_lock(L);
  if (!obj->ptr) goto out;
  use(obj->ptr);
  spin_unlock(L);
- Another path writes to the same pointer (e.g., sets it to NULL) without holding L:
  obj->ptr = NULL;  // no lock

This violates the locking discipline for the shared field, creating a TOCTOU race where the pointer can change between the check and use, leading to a possible NULL pointer dereference.
