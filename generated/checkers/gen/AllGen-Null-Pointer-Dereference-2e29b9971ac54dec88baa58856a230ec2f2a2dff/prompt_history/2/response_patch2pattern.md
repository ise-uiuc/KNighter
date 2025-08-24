## Bug Pattern

After allocating memory into one pointer/field, the code checks a different pointer/field for NULL. This mis-validated allocation causes allocation failures to go unnoticed (or incorrect early returns), leading to invariant violations or NULL dereferences later.

Example:
p = kzalloc(size, GFP_KERNEL);
if (!q)  // BUG: should check p, not q
    return -ENOMEM;
