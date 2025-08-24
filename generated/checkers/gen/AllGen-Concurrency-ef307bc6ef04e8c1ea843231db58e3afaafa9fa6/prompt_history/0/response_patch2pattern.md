## Bug Pattern

Updating a shared, lock-protected pointer (e.g., urb->hcpriv) outside of its protecting lock, while other code checks and then uses that pointer under the lock.

- Writer (buggy): releases hsotg->lock and then sets urb->hcpriv = NULL.
- Reader: under hsotg->lock does:
  if (!urb->hcpriv) goto out;
  use(urb->hcpriv);

This inconsistent locking allows a concurrent NULL assignment to race between the check and the use, causing a NULL pointer dereference. The fix is to perform the pointer update (setting to NULL) while still holding the same lock that guards reads/uses of the pointer.
