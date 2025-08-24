## Bug Pattern

In a loop that allocates and initializes per-item resources (e.g., alloc_etherdev()), an error occurring mid-iteration before the item is fully registered/committed jumps to a common cleanup that tears down only previously completed iterations (e.g., while (--idx >= 0)), thereby excluding the current (failed) iteration. As a result, resources allocated in the current iteration (the net_device) are not freed, causing a memory leak. The fix is to explicitly free the current iteration’s resource before jumping to the shared exit path.
