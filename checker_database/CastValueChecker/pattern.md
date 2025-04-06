```
## Bug Pattern

Performing custom RTTI casts (such as llvm::cast, dyn_cast, cast_or_null, etc.) on a value without ensuring that its dynamic type actually matches the target type. In this pattern, the code assumes that a cast will succeed (or be checked as successful) even when the dynamic type information indicates that the conversion is infeasible. This faulty assumption can lead to generating an incorrect, null, or sink state, reflecting an improper use of type‐casting functions where the static and dynamic types are inconsistent.
```