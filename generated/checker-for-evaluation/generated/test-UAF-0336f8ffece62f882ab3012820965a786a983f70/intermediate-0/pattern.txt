## Bug Pattern

The bug pattern is the use-after-free issue caused by invoking free_netdev() before canceling work that uses netdev’s private data. In the buggy code, the network device is freed (thereby invalidating its associated private data) prior to calling cancel_work_sync() on a workqueue that still references that data, leading to a potential UAF scenario.