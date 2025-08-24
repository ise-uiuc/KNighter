## Bug Pattern

Indexing fixed-size LUT arrays with a computed index without validating the index against the array’s bound. Specifically, using a loop-controlled, arithmetic-derived index (i) to access output_tf->tf_pts.{red,green,blue}[i] while terminating the loop based on a different counter (j/hw_points), and without checking i < TRANSFER_FUNC_POINTS, which can lead to out-of-bounds array access.
