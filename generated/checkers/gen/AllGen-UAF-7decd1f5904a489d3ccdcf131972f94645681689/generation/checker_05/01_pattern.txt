## Bug Pattern

Reading a field from an object after calling a function that can free (or start freeing) that object.

Concrete form:
- Code calls a “close/destroy” routine (e.g., mptcp_close_ssk(obj)), which may release the object (often via RCU/async).
- After returning, code accesses the object’s fields (e.g., obj->request_join), sometimes even after dropping and re-acquiring locks.
- This creates a use-after-free read.

Identifiable pattern in code:
- unlock
- close_or_free(obj)
- lock
- use obj->field  // UAF

Correct pattern:
- read/cache needed fields from obj before calling the close/free routine, or hold a refcount that guarantees lifetime across the call.
