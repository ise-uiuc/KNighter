## Bug Pattern

Allocating one pointer but checking a different pointer for NULL.

Example pattern:
ptrA = kzalloc(size, GFP_KERNEL);
if (!ptrB)
    return -ENOMEM;

Here, the allocation result (ptrA) is not validated, while an unrelated pointer (ptrB) is checked. This misses allocation failures of ptrA, violating invariants and risking later NULL dereference or inconsistent state.
