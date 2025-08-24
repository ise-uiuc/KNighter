## Bug Pattern

Looping with a bound derived from one constant/enumeration (e.g., __DML_NUM_PLANES__) and using that loop index to access arrays sized by a different, smaller limit (e.g., __DML2_WRAPPER_MAX_STREAMS_PLANES__) without validating the index. This mismatch causes out-of-bounds array access (disp_cfg_to_stream_id[i], disp_cfg_to_plane_id[i]) when the loop bound exceeds the array size.
