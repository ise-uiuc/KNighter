## Bug Pattern

Calling a high-level “close/free” routine in a partial-initialization error path, causing resources to be freed twice when the top-level cleanup runs.

Concretely: after creating a hardware SQ but before fully opening it (set to ready), the code used hws_send_ring_close_sq(sq) on failure. That “close” frees software-owned buffers (e.g., sq->dep_wqe, sq->wq_ctrl.buf.frags, sq->wr_priv) that the caller also frees during its unwind, leading to double-free. The correct cleanup at this stage is the matching low-level destroy of only the last acquired resource (mlx5_core_destroy_sq), not the full close that assumes full initialization.
