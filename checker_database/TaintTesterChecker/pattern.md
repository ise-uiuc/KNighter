```
## Bug Pattern

Using data that is marked as tainted without proper sanitization. In this pattern, expressions (or values) that satisfy a taint condition are used unchecked, which may allow unsafe or untrusted data to propagate through the program and trigger security issues.
```