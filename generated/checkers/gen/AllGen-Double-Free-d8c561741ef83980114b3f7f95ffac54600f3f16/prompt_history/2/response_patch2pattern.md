## Bug Pattern

Using a full teardown/close routine in a mid-initialization error path, instead of rolling back only the step that just succeeded. Specifically, after creating a hardware SQ but failing to transition it to ready, the code called a "close" helper that frees software resources (e.g., WQ buffers, private structs) that are also freed later by the higher-level error cleanup, causing double free. The correct pattern is to call the matching hardware destroy function (mlx5_core_destroy_sq) for that partial state, not the full close routine.
