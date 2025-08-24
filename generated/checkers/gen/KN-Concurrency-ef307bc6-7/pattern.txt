## Bug Pattern

Modifying a shared, lock-protected pointer (urb->hcpriv) without holding its protecting spinlock (hsotg->lock), while other code checks and uses that pointer under the lock. Specifically, releasing the lock before updating the pointer (unlock-before-state-update) creates a TOCTOU race where another thread can observe the pointer as non-NULL under the lock, then the first thread sets it to NULL outside the lock, leading to a NULL dereference when the second thread uses the stale value.

Pattern snippet:

- Thread A (incorrect):
  spin_unlock_irqrestore(&lock, flags);
  shared_ptr = NULL;  // update happens outside lock

- Thread B (concurrent):
  spin_lock_irqsave(&lock, flags);
  if (shared_ptr)
      use(shared_ptr);  // assumes shared_ptr won’t change while locked

Root cause: Writing to a field that is read-checked-and-used under a specific lock without holding that same lock.
