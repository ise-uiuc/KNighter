## Bug Pattern

Inconsistent locking on a shared pointer: one path reads/checks and uses a shared pointer field (urb->hcpriv) while holding a lock (hsotg->lock), but another path writes/clears that same field without holding the same lock (or after unlocking). This lock mismatch causes a race where the reader’s “check-then-use” inside the critical section can become invalid if the writer clears the pointer concurrently, leading to a NULL pointer dereference.

Typical form:
- Reader:
  spin_lock(&lock);
  if (ptr)
      use(ptr);  // assumes ptr won’t change while lock is held
  spin_unlock(&lock);

- Writer (buggy):
  // no lock held (or after unlocking)
  ptr = NULL;  // updates shared state without the protecting lock

Root cause: Modifying a lock-protected shared pointer outside its protecting lock, breaking the atomicity assumed by code that checks and uses it under the lock.
