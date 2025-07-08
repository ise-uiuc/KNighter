```
## Bug Pattern

The bug pattern is an improper cleanup in an error handling path that leads to double-freeing resources. In the error path, the wrong cleanup function (hws_send_ring_close_sq) is invoked, which frees parts of the SQ resources (such as dep_wqe, wq_ctrl.buf.frags, and wr_priv) that are either already freed or that will be freed subsequently. The root issue lies in using a cleanup routine meant for normal shutdown instead of a dedicated destruction function designed for the error path, causing the same memory to be freed twice.
```