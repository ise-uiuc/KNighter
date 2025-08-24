## Bug Pattern

Index/size mismatch across different arrays: iterating an index i using the bound of one domain (e.g., __DML_NUM_PLANES__) and then using that same i to access arrays that are smaller (bounded by __DML2_WRAPPER_MAX_STREAMS_PLANES__) without validating i against the smaller bound, causing potential out-of-bounds access.

Example:
for (i = 0; i < SIZE_A; i++) {         // SIZE_A >= SIZE_B
    ... = array_B[i];                  // array_B has SIZE_B elements
    ... = array_C[i];                  // array_C has SIZE_B elements
}
