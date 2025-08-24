## Bug Pattern

Updating a shared pointer field outside the lock that protects it, while other code checks and uses that pointer under the lock, causing a check-then-use race. Concretely:

- Reader path:
  - spin_lock(&L);
  - if (obj->ptr) use(obj->ptr);
  - spin_unlock(&L);

- Writer path:
  - obj->ptr = NULL;   // done without holding L (or after releasing L)

Because the writer clears obj->ptr without holding the same lock L, the reader can observe obj->ptr as non-NULL at the check and then have it become NULL before the use, leading to a NULL pointer dereference.
