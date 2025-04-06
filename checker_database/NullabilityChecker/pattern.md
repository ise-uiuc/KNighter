```
## Bug Pattern

The bug pattern is the violation of nullability contracts. This occurs when a pointer that is required to be nonnull (by its annotation or intended design) is either assigned or produced as null (or comes from a nullable source) and then used unchecked. In other words, the bug arises when null or nullable pointers are passed to locations or functions that expect nonnull values—or when such pointers are dereferenced without a proper null check—thus violating the declared pointer’s nonnull guarantee.
```