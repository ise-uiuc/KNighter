## Bug Pattern

Incorrect NULL-check after allocation: a pointer returned by kzalloc()/kmalloc() is assigned to one field but the code checks a different (unrelated) pointer for NULL. Concretely:
- ptr1 = kzalloc(...);
- if (!ptr2) return -ENOMEM;  // should check ptr1

In the patch, dst->thread.sve_state is allocated, but the code erroneously checks dst->thread.za_state, allowing an allocation failure of sve_state to go unnoticed and leading to inconsistent state or potential NULL dereference later.
