## Bug Pattern

Freeing the context structure of a queued work item in the caller on timeout while the worker still assumes the structure is valid and uses it (e.g., to call complete() or to free it). The lifetime of the shared reset/request struct is not coordinated between the submitter and the worker, leading to a use-after-free when the worker dereferences or frees memory already freed by the caller.

Typical pattern:

- Caller:
  struct ctx { struct work_struct work; struct completion done; ... } *c = kzalloc(...);
  init_completion(&c->done);
  INIT_WORK(&c->work, worker);
  queue_work(wq, &c->work);
  if (!wait_for_completion_timeout(&c->done, t))
      kfree(c);  // timeout frees context

- Worker:
  struct ctx *c = container_of(work, struct ctx, work);
  ... do work ...
  complete(&c->done);        // or kfree(c) in async mode
  // uses c after caller may have freed it on timeout

Missing check like completion_done(&c->done) to decide who owns freeing after a timeout causes UAF.
