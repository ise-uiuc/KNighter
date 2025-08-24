## Bug Pattern

Dereferencing the result of a devm_* allocation without checking for NULL.

Pattern:
- Allocate a sub-structure with devm_kzalloc (or similar devm_* allocator) and immediately use it (e.g., via a local alias) without validating the allocation succeeded.

Example pattern:
```
p = devm_kzalloc(dev, size, GFP_KERNEL);
q = p;                  // alias
q->field = ...;         // NULL dereference if allocation failed
```

This commonly appears in probe paths or loops allocating per-instance objects (e.g., array elements) where the pointer (spi_bus->spi_int[iter]) is used before an explicit NULL check.
