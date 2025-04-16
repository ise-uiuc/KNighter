```
## Bug Pattern

Deleting a polymorphic object (or an array of polymorphic objects) through a base class pointer whose type does not properly reflect the object's dynamic type—specifically when the base class lacks a virtual destructor. This mismatch in type information during deletion can lead to undefined behavior, as the correct destructor (or destructors for arrays) may not be invoked. The pattern is characterized by:
• Converting a pointer from a derived (dynamic) type to a base type that does not declare its destructor virtual.
• Deleting an object or array through such a pointer, which can result in incomplete destruction of the object(s).
```