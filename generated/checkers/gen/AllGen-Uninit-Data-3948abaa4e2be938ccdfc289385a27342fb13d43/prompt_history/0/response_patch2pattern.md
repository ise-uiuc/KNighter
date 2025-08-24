## Bug Pattern

Allocating a buffer with kmalloc() that will be copied to user space, but not initializing all bytes that are copied (e.g., struct header + flexible array/padding where the encoder fills only part of the payload). This leaves tail or padding bytes uninitialized, and copy_to_user() leaks them to user space.

Typical form:
- p = kmalloc(total);
- fill only some fields/payload bytes;
- copy_to_user(user, p, total);

Fix: zero-initialize the buffer (kzalloc/memset) or copy only the initialized portion.
