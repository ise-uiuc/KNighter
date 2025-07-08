## Bug Pattern

Failing to free dynamically allocated memory in an error-handling path. In this case, when rvu_rep_devlink_port_register() fails, the netdev allocated earlier is not freed, causing a memory leak. The root issue is the missing cleanup for an allocated resource before aborting further processing, which can lead to memory leaks if similar error paths are not handled properly.