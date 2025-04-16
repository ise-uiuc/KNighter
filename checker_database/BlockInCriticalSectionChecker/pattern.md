```
## Bug Pattern

Calling blocking functions (e.g. sleep, getc, fgets, read, recv) while a mutex is held or inside a critical section. This pattern arises when code enters a region protected by a lock (or similar synchronization mechanism) and then invokes an operation that can block execution. Such a call may delay progress or even lead to deadlock because it prevents other threads from acquiring the lock, creating a potential performance bottleneck or system deadlock.
```