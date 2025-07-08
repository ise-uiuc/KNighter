## Bug Pattern

Exposing a partially‐initialized object to user space by publishing its ID (via xa_alloc) before all its critical members (e.g. reference count via q->xef) have been set. This premature publication creates a window where an attacker can trigger a destroy (free) on the object, resulting in a use‐after‐free vulnerability.