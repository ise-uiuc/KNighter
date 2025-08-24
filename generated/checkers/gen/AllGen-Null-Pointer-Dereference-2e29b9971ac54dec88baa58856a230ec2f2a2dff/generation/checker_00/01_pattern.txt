## Bug Pattern

Checking the wrong pointer for NULL after allocation. Specifically, after allocating dst->thread.sve_state with kzalloc(), the code mistakenly tests dst->thread.za_state instead of dst->thread.sve_state. Because the entire task_struct was previously copied from src, dst->thread.za_state may still be non-NULL, causing the allocation failure of sve_state to go undetected and leaving the structure in an inconsistent state.
