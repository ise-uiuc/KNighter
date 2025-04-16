```
## Bug Pattern

The checker flags cases where an Objective‑C generic object’s dynamic type (including its specialized type arguments) does not match or is incompatible with the static type expected at a cast or message send. In other words, when code uses casts or sends messages to objects whose inferred (dynamic) type information—including generic parameter details—differs from the static (declared) type, it may result in an invalid type conversion. This pattern of “mismatched generic type propagation” (i.e. loss or incorrect inference of specialization information) can lead to bugs where the runtime type does not conform to the expected interface, resulting in potentially unsafe conversions.
```