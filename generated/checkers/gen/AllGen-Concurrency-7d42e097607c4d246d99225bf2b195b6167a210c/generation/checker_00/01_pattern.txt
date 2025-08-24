## Bug Pattern

Uncoordinated lifetime management of a workqueue context that is shared between the caller and the worker when using wait_for_completion_timeout():

- The caller allocates a context (container of work_struct), queues the work, and waits on a completion with a timeout.
- On timeout, the caller frees the context unconditionally, while the worker still holds and later dereferences the same context (e.g., to call complete() or to free it), leading to use-after-free/double-free.

Characteristic code pattern:

- Caller:
  - ctx = kmalloc(...);
  - queue_work(..., &ctx->work);
  - if (!wait_for_completion_timeout(&ctx->done, timeout)) {
      kfree(ctx);  // BUG: worker still owns/uses ctx
    } else {
      kfree(ctx);
    }

- Worker:
  - ctx = container_of(work, typeof(*ctx), work);
  - ... uses ctx ...
  - complete(&ctx->done);
  - possibly kfree(ctx) for async mode.

Fix pattern: Only free the context on the side that “owns” it at that moment—use completion_done(&ctx->done) in the worker to detect caller timeout and free there, and in the caller free only when completion succeeded.
