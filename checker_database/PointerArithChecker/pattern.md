```
## Bug Pattern

Performing pointer arithmetic on pointers that do not point to valid array elements. In this pattern, arithmetic operations (such as addition, subtraction, or increment/decrement) are applied to pointers referencing single objects or regions not allocated as arrays, relying on memory layout assumptions that may be invalid. This misuse can lead to undefined behavior and potential memory access errors when the pointer arithmetic goes out-of-bounds of the intended object.
```