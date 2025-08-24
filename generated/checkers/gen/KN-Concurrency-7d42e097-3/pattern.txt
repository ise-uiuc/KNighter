## Bug Pattern

Freeing a work item’s context structure in the scheduler’s timeout path while the workqueue worker still references it (e.g., to signal a completion), causing a use-after-free.

Typical shape:
- A worker uses container_of(work, ctx, work) to access a heap-allocated ctx that also holds a completion for synchronous callers.
- The caller schedules the work and waits with wait_for_completion_timeout(&ctx->done, tmo).
- On timeout, the caller unconditionally kfree(ctx), but the worker will later access ctx (e.g., complete(&ctx->done) or other fields), leading to UAF.
- Ownership/lifetime of ctx is not clearly separated between the caller and the worker, especially for the timeout case.

Fix pattern:
- Only free ctx in one place depending on whether the waiter is still waiting or has timed out (e.g., use completion_done() to decide), and avoid freeing on both sides or freeing on timeout while the worker still runs.
