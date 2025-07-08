```
## Bug Pattern

The bug pattern involves improper coordination of memory ownership between asynchronous and synchronous completion paths leading to a race condition and subsequent use‐after‐free. Specifically, the structure containing the work (reset_data) is freed in two different contexts (the worker and the scheduling function) without a reliable mechanism to determine if the caller is still waiting on a completion. When the caller times out and frees the structure while the worker is still about to use or complete it, a race occurs, which results in a use‐after‐free bug. The pattern is characterized by the lack of proper synchronization (e.g., not checking if a completion has already been signaled) before freeing a shared resource in asynchronous recovery flows.
```