## Bug Pattern

The bug pattern is an error-path cleanup issue where the same resource is freed twice. In this case, if an error occurs, one cleanup function (fastrpc_req_munmap_impl()) already frees the buffer "buf" and then an unconditional subsequent call to fastrpc_buf_free() also frees it. This overlapping cleanup logic leads to a double free, which can cause undefined behavior or crashes.