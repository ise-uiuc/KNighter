```
## Bug Pattern

Detecting direct conversion or comparison of pointers that represent number or boolean objects (such as NSNumber, OSNumber, CFNumberRef, etc.) to primitive scalar types (like integers or booleans) without first invoking the proper accessor methods. This typically happens when a pointer is reinterpreted as a numeric value directly (or is compared against a scalar) instead of extracting the contained value through the correct API (e.g., using -boolValue, getValue(), or CFNumberGetValue()). Such misuse can lead to logic errors because the address of the object (the pointer) is used rather than the actual numerical value stored inside the object.
```