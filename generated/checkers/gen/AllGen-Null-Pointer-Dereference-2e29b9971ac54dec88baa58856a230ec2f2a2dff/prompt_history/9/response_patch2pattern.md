## Bug Pattern

Mismatched NULL check after allocation: allocate one field/pointer but test a different field for failure. Concretely, code does:
dst->thread.sve_state = kzalloc(...);
if (!dst->thread.za_state) return -ENOMEM;
so the allocation result for sve_state is never validated. Because dst was copied from src earlier, za_state may be non-NULL, letting the failure go unnoticed and leaving the structure in an inconsistent state.
