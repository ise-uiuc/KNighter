## Bug Pattern

Checking the wrong pointer for NULL after an allocation. Specifically, after allocating one field (e.g., dst->thread.sve_state = kzalloc(...)), the code erroneously tests a different field (dst->thread.za_state) for NULL, causing allocation failures to be missed and leaving related state inconsistent.

Example:
p->sve_state = kzalloc(...);
if (!p->za_state)   // BUG: should be !p->sve_state
    return -ENOMEM;
