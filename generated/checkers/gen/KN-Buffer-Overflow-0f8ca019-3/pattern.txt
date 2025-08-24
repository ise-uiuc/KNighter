## Bug Pattern

Indexing an array using a loop bound defined by a different (larger) compile-time constant than the array’s actual size. Specifically:
- Loop iterates with i < __DML_NUM_PLANES__, but accesses arrays sized to __DML2_WRAPPER_MAX_STREAMS_PLANES__:
  disp_cfg_to_stream_id[i] and disp_cfg_to_plane_id[i].
- Missing bounds check allows i to exceed the arrays’ capacity, causing out-of-bounds access (buffer overflow).
