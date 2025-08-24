## Bug Pattern

Using an over-scoped cleanup routine in an intermediate error path. Specifically, after partially creating an object (HW SQ created but not fully initialized), the code calls a high-level “close” helper that frees both HW and driver-owned SW resources, while the caller’s error unwinding later frees the same SW resources again. The correct pattern is to unwind only the last successful step (e.g., call the HW-only destroy function) rather than a full “close” that also frees SW state, to avoid double free.
