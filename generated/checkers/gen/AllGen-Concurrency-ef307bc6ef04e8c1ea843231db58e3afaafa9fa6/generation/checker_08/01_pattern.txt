## Bug Pattern

Inconsistent locking on a shared pointer leading to a check-then-use race:
- One path reads and checks a shared pointer under a spinlock and then uses it:
  spin_lock(&lock);
  if (!obj->ptr)
      goto out;
  use(obj->ptr);
  out:
  spin_unlock(&lock);
- Another path clears the same pointer outside the protecting lock:
  /* no lock held */
  obj->ptr = NULL;

Because the writer updates the pointer without holding the lock, the reader can pass the NULL check and then observe the pointer become NULL before use, causing a NULL pointer dereference. The fix is to perform the pointer update (obj->ptr = NULL) while holding the same lock.
