```
## Bug Pattern

Declaring an Objective-C property with the copy attribute for a mutable object type (i.e. a type whose name begins with "NSMutable") can lead to unexpected behavior. When the property is synthesized without a user-declared setter, the automatically generated setter calls −copy on the value, which produces an immutable copy. This mismatch between the property’s declared mutable type and the stored immutable object is the general bug pattern.
```