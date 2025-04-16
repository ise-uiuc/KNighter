```
## Bug Pattern

Capturing a local variable in a block without first initializing it. When a block captures a variable that has an undefined value at the time of capture, it may later lead to the use of uninitialized data when the block is executed. This pattern applies to any situation where a block (or closure) forms a reference to a variable that has not been properly initialized in its original context.
```