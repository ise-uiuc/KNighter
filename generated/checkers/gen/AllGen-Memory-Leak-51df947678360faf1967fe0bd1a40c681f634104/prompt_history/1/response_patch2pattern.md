## Bug Pattern

In a loop that creates multiple net_devices, an error occurs after alloc_etherdev() but before the device is fully registered/owned (e.g., devlink port registration fails). The code jumps to a common exit handler whose cleanup loop frees only previously created items using a pre-decrement index (while (--idx >= 0) ...), which skips the current iteration. Because the current net_device is not explicitly freed before goto exit, it leaks.
