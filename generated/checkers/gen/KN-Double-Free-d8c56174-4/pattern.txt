## Bug Pattern

Using an over-broad “close/free-all” cleanup routine in an intermediate error path of partial initialization. Specifically, after successfully creating a HW SQ but failing to transition it to ready, the code called hws_send_ring_close_sq(sq), which frees software-side allocations (e.g., sq->dep_wqe, sq->wq_ctrl.buf.frags, sq->wr_priv) that will be freed again by the outer error-unwind, causing double free. The correct pattern is to call the matching low-level destroy (mlx5_core_destroy_sq) for the created HW object only.

Example:
```
err = hws_send_ring_set_sq_rdy(mdev, sq->sqn);
if (err)
    hws_send_ring_close_sq(sq);  // Wrong: frees too much; leads to double free later
// Should be:
if (err)
    mlx5_core_destroy_sq(mdev, sq->sqn);  // Only undo the created HW SQ
```
