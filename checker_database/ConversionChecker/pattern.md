```
## Bug Pattern

Implicit conversions where the source type can hold values (especially negative values or values with higher precision) that cannot be accurately represented by the destination type. In particular, converting:
• a signed integer to an unsigned integer (leading to loss of sign),
• or a larger integer to a smaller integer or a floating point type that cannot represent all values in the source’s range (leading to loss of precision).

This pattern appears in assignments, initializations, and arithmetic operations where the implicit cast may truncate the value or misinterpret its sign, resulting in potentially incorrect computations.
```