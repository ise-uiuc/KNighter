## Bug Pattern

After allocating one pointer, the code checks a different pointer for NULL. Specifically:
- ptrA = kzalloc(...);
- if (!ptrB) return -ENOMEM;  // should check ptrA

This mismatched NULL check (verifying an unrelated field instead of the just-allocated one) lets allocation failures go unnoticed, leading to inconsistent state and potential misuse of a NULL pointer.
