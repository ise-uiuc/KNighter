## Bug Pattern

Exiting early from an iterative resource-creation loop after allocating a net_device but before registering it, while the shared cleanup block only frees resources from previous iterations (using a pre-decrement index), leaving the current iteration’s allocation unfreed.

In code form:

for (i = 0; i < cnt; i++) {
    ndev = alloc_etherdev(...);     // allocation
    if (!ndev) goto exit;

    if (rvu_rep_devlink_port_register(...))  // fails before register_netdev()
        goto exit;                             // missing free_netdev(ndev) here
    register_netdev(ndev);
}
exit:
while (--i >= 0) {      // cleans only iterations [0..i-1]
    unregister_netdev(rep[i]->netdev);
    free_netdev(rep[i]->netdev);
}

Root cause: Not freeing the per-iteration resource on the failure path between alloc_etherdev() and register_netdev(), combined with a cleanup loop that intentionally skips the current (partially initialized) iteration.
