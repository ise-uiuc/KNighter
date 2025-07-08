## Bug Pattern

A failure to release allocated memory (resource leak) on an error path. In this case, when the function rvu_rep_devlink_port_register() fails, the code does not immediately free the allocated network device (using free_netdev(ndev)) before jumping to the error exit, causing a memory leak.