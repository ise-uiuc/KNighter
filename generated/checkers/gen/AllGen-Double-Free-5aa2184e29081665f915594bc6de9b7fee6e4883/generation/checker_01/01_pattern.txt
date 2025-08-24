## Bug Pattern

Using a single error cleanup path that frees resources unconditionally, even when the failure occurred before those resources were successfully allocated or when the callee already freed them. Specifically, after hws_definer_conv_match_params_to_hl() fails, jumping to a label that kfree(mt->fc) can double-free mt->fc (or free an uninitialized pointer), because the callee may have already freed/not allocated it. The fix separates cleanup labels so only the memory definitely owned at that point (match_hl) is freed on that path.
