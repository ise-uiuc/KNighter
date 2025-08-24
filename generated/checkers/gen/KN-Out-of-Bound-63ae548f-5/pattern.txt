## Bug Pattern

Using a computed index to access a fixed-size LUT without validating it:
- The loop terminates based on a different counter (j/hw_points), while array access uses another counter (i) computed from region/segment math (start_index, increment).
- No check ensures i < TRANSFER_FUNC_POINTS before indexing output_tf->tf_pts.{red,green,blue}[i].
- This decoupling of loop termination and the indexed array’s bounds allows i to exceed the array size, causing out-of-bounds access.
