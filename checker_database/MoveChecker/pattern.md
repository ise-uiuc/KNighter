```
## Bug Pattern

Detecting and reporting the use‐of an object that has been “moved from.” In other words, the checker identifies when an object (tracked via its memory region) has been subject to a move (move construction or move assignment), which transfers its internal resources and leaves it in a valid but unspecified state, and then is subsequently used (via method calls, copy/move operations, or dereferencing) in ways that assume it is still fully initialized. This misuse of a moved-from object constitutes the bug pattern.
```