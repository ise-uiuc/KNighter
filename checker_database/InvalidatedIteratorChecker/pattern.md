```
## Bug Pattern

The bug pattern is the use of iterators after they have been invalidated. Specifically, code that continues to dereference or access iterators without verifying that their underlying position remains valid (after container modifications, for example) risks undefined behavior. This pattern occurs when iterator validity is not checked before operations that assume a valid iterator state.
```