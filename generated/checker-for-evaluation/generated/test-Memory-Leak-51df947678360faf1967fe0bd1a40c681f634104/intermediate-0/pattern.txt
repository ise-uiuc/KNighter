## Bug Pattern

Failure to properly free an allocated resource upon encountering an error in an initialization sequence. In this case, when a subroutine (rvu_rep_devlink_port_register) fails, the allocated net_device (ndev) is not freed before exiting, leading to a memory leak. This pattern occurs when error paths neglect to clean up partially initialized resources, resulting in resource leaks.