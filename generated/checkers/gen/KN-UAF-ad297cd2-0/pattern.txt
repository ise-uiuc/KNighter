## Bug Pattern

Calling free_netdev(netdev) before all cleanup that still dereferences the driver’s private data (netdev_priv(netdev)). After free_netdev() the private area is freed, so any subsequent use like adpt->... (iounmap, put/unregister, etc.) is a use-after-free.
