## Bug Pattern

Modifying a lock-protected shared pointer after dropping the lock, racing with another path that checks-and-uses the same pointer while holding the lock. Concretely:

- One path holds hsotg->lock and does:
  - if (!urb->hcpriv) … else use(urb->hcpriv)
- Another path releases hsotg->lock and then does:
  - urb->hcpriv = NULL;

This violates the locking discipline for urb->hcpriv, creating a TOCTOU race where the reader observes non-NULL under the lock, the writer clears it without the lock, and the reader then dereferences a NULL/stale pointer.
