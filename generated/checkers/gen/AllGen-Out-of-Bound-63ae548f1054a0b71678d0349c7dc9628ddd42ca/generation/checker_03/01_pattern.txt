## Bug Pattern

Indexing fixed-size transfer-function LUT arrays with a computed index derived from region/segment arithmetic without validating the index against the array bound (TRANSFER_FUNC_POINTS), e.g.:

for (...) {
    // i computed from region/segment math
    // Missing: if (i >= TRANSFER_FUNC_POINTS) error/return
    val_r = output_tf->tf_pts.red[i];
    val_g = output_tf->tf_pts.green[i];
    val_b = output_tf->tf_pts.blue[i];
}

This lack of bounds checking can lead to out-of-bounds reads when i (or start_index) exceeds TRANSFER_FUNC_POINTS.
