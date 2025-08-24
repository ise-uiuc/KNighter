## Bug Pattern

Mismatched teardown in a multi-stage init: on failure of a late step (e.g., setting an SQ to Ready), the code calls a high-level “close/free-all” routine that releases both HW and SW resources (e.g., dep_wqe, wq_ctrl.buf.frags, wr_priv) instead of invoking the precise inverse of the last successful step (e.g., only destroying the HW SQ). This causes those SW resources to be freed again by the normal unwind path, leading to double-free.
