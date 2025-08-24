## Bug Pattern

Indexing a fixed-size LUT array with a computed index that is not validated against the array’s capacity. Specifically, using an index i derived from region/segment calculations to access output_tf->tf_pts.{red, green, blue}[i] without ensuring 0 <= i < TRANSFER_FUNC_POINTS, allowing out-of-bounds reads when i reaches or exceeds TRANSFER_FUNC_POINTS.
