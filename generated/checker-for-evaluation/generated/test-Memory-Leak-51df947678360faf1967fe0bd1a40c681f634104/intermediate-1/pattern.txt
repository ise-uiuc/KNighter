## Bug Pattern

Failure to free a dynamically allocated resource in an error path. In this case, when rvu_rep_devlink_port_register() fails, the allocated net_device (ndev) is not freed before exiting, leading to a memory leak. This pattern occurs when error checking is incomplete, and allocated objects are not properly deallocated if subsequent initialization steps fail.