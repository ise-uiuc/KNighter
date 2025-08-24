## Bug Pattern

Indexing a fixed-size LUT with a derived loop index without validating it against the LUT’s bound. Specifically, using:
- output_tf->tf_pts.{red, green, blue}[i]
where i is computed from region/segment arithmetic (start_index, increment) and the loop is controlled by j/hw_points rather than by the array bound TRANSFER_FUNC_POINTS. This missing check allows i to reach/exceed TRANSFER_FUNC_POINTS, causing out-of-bounds access.
