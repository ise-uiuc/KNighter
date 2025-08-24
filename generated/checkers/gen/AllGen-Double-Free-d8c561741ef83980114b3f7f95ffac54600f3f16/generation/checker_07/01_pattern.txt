## Bug Pattern

Using a full “close”/composite cleanup helper on a partially initialized object in an error path, instead of the stage-matched low-level destroy routine, causing resources to be freed twice.

Concretely: after successfully creating an SQ (mlx5_core_create_sq) but failing to set it Ready, the code called hws_send_ring_close_sq(sq), which tears down both HW and SW allocations (dep_wqe, wq_ctrl.buf.frags, wr_priv) that are also freed by the higher-level error unwinder. The correct pattern is to call only mlx5_core_destroy_sq() at that stage, matching what has been allocated so far, and leave the rest to the outer cleanup to avoid double-free.
