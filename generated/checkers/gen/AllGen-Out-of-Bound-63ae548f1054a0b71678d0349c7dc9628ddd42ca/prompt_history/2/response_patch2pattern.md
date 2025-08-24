## Bug Pattern

Indexing fixed-size LUT arrays with an algorithmically computed index without validating it against the array’s maximum size:
- Accesses like `output_tf->tf_pts.{red,green,blue}[i]` use an `i` derived from region/segment math (`start_index`, `increment`) but do not check `i < TRANSFER_FUNC_POINTS`.
- This can drive `i` beyond the valid range (e.g., for large `start_index` or step rounding), causing out-of-bounds reads from the `tf_pts` arrays.
