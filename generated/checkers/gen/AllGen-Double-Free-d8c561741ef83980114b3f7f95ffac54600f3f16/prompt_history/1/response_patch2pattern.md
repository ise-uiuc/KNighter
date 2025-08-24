## Bug Pattern

Using a full “close”/finalizer routine in a partial-initialization error path instead of the exact destroy/undo pair for the last successful step. Specifically, after successfully calling mlx5_core_create_sq() but failing the subsequent set-to-ready step, the code called hws_send_ring_close_sq() (which frees software-owned resources that will be freed again later), rather than the matching rollback mlx5_core_destroy_sq(). This mismatch in teardown (close vs destroy) on intermediate failure leads to double-free of SQ-owned buffers/priv data.
