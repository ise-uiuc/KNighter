## Bug Pattern

Indexing an array using a loop bound defined by a different (and potentially larger) macro than the array’s actual size, without validating the index against the array’s own bound.

Example:
- Loop uses i in [0, __DML_NUM_PLANES__)
- Arrays disp_cfg_to_stream_id[] and disp_cfg_to_plane_id[] are sized to __DML2_WRAPPER_MAX_STREAMS_PLANES__
- Code accesses disp_cfg_to_*[i] without checking i < __DML2_WRAPPER_MAX_STREAMS_PLANES__, causing out-of-bounds when __DML_NUM_PLANES__ > __DML2_WRAPPER_MAX_STREAMS_PLANES__
