## Bug Pattern

Use-after-free due to freeing the net_device before the last use of its private data:
- Obtain adapter pointer from netdev_priv(netdev).
- Call free_netdev(netdev) (which frees the private data).
- Continue to dereference the adapter (e.g., adpt->... for iounmap/MDIO/etc.).

In short: dereferencing netdev_priv(netdev) after calling free_netdev(netdev) because of incorrect teardown order.
