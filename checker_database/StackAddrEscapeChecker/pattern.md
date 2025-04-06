```
## Bug Pattern

The bug pattern is the escape of a pointer to stack-allocated memory out of its valid lifetime. Specifically, a pointer that references memory allocated on the stack (e.g., local variables, alloca results, compound literals, or stack-based blocks) is returned or stored into a global or heap location. This causes the pointer to be used after its associated stack frame has been destroyed, leading to dangling pointer accesses and undefined behavior.
```