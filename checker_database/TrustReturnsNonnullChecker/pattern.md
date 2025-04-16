```
## Bug Pattern

Trusting a function’s non-null guarantee solely based on its "returns_nonnull" attribute, without performing any explicit runtime check. In this pattern, pointers returned from functions annotated with "returns_nonnull" are automatically assumed to be non-null, which can mask issues if the function mistakenly returns a null pointer.
```