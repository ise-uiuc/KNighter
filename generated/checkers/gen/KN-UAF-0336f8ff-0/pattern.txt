## Bug Pattern

Calling free_netdev(dev) before canceling/flushing deferred work that resides in or accesses netdev’s private data. Specifically:
- priv = netdev_priv(dev) is used after free_netdev(dev)
- Example: free_netdev(dev); cancel_work_sync(&priv->work);
This order frees the net_device (and its private area), then uses priv, causing a use-after-free. The correct pattern is to cancel/flush all work/timers/IRQs that may touch priv before calling free_netdev().
