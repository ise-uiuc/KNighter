## Bug Pattern

In a per-item creation loop:
- A resource is allocated for the current iteration (e.g., ndev = alloc_etherdev(...)).
- A later step in the same iteration fails before the resource is fully registered/added to the list/array that the common exit path cleans up.
- The error path uses a shared cleanup block that frees only previously created items (e.g., while (--i >= 0) { ... }), thus skipping the current (failed) iteration.
- The code jumps to this shared cleanup without first releasing the just-allocated resource, causing a memory leak.

Concretely: allocating a net_device inside a loop, then on failure (e.g., devlink_port_register error) doing goto exit, where exit only unregisters/frees indices < current via --rep_id, leaving the current ndev unfreed. The fix is to free the current resource before goto exit when the failure occurs prior to it being accounted for by the shared cleanup.
