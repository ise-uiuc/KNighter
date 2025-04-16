```
## Bug Pattern

Overriding an Objective-C instance method in a subclass with a return type that is not compatible with the return type declared in the superclass (or interface). This mismatch in method signatures—specifically in the return types—can lead to undefined behavior for clients expecting a consistent type across the inheritance chain.
```