## Bug Pattern

Error path in a per-iteration creation loop jumps to a common cleanup that only releases previously created items (using a pattern like `while (--idx >= 0) cleanup(prev[idx]);`). If a resource is allocated in the current iteration and an error occurs before the index is decremented, failing to explicitly free that current resource before `goto exit;` leaks it. Concretely:

- Allocate per-iteration resource (e.g., `ndev = alloc_etherdev(...)`).
- On subsequent failure (e.g., `rvu_rep_devlink_port_register(rep)`), directly `goto exit;` without `free_netdev(ndev)`.
- The exit cleanup loop starts with `--rep_id`, so it only frees indices < current, leaving the current partially initialized resource leaked.

Pattern snippet:

ndev = alloc_etherdev(...);
if (!ndev) goto exit;

err = step_after_alloc(...);
if (err)
    goto exit;  // missing free(ndev) here → leak

exit:
while (--idx >= 0)
    cleanup(prev[idx]);  // does not handle current iteration
