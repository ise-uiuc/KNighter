## Bug Pattern

Freeing a work item’s heap-allocated context from the submitter after a timed wait while the queued worker still references that context.

Concretely:
- A structure embedding work_struct and a completion is allocated and queued to a workqueue.
- The submitter waits with wait_for_completion_timeout().
- On timeout it frees the context.
- The worker later dereferences the same context (to complete() or kfree()), causing a use-after-free or double-free.

Root cause: No ownership/serialization between the submitter and the worker about who frees the shared context when the wait times out. The fix ensures only one side frees it by checking completion_done() (or equivalent coordination) before using/freeing the context.
