## Bug Pattern

Freeing the work item’s context from the submitting thread after a timeout while the worker still uses that context. Specifically:
- A heap-allocated structure (containing a completion and work_struct) is shared between the submitter and the worker.
- The submitter waits for completion with a timeout and frees the structure on timeout.
- The worker, unaware of the timeout, unconditionally accesses the structure (e.g., calls complete() or reads fields), causing a use-after-free.
- Ownership/lifetime is split by a mode flag (sync/async) but does not account for the sync timeout case; there is no check (e.g., completion_done()) in the worker to detect that the waiter gave up and transferred freeing responsibility.
