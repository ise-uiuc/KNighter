## Bug Pattern

Indexing into a fixed-size transfer-function LUT (output_tf->tf_pts.{red, green, blue}) using a computed loop index (i) derived from region offsets and increments without validating that i < TRANSFER_FUNC_POINTS. The arithmetic used to compute start_index and step can produce i values that exceed the LUT length, leading to out-of-bounds array access.
