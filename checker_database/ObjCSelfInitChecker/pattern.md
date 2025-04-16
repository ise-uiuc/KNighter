```
## Bug Pattern

Using the 'self' object before it has been properly re-assigned from an initializer call. In other words, in Objective-C initializer methods, if the object referenced by 'self' is used (for example, to access instance variables or to be returned) without first assigning 'self' to the result of an initialization method (such as [super init] or [self init…]), then the object may be in an invalid or uninitialized state. This pattern of not updating 'self' with the initializer’s result before its use is the root cause of the bug.
```