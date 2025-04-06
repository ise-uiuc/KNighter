## Bug Pattern

Declaring a variable-length array (VLA) with an invalid size expression – that is, when the size is derived from a value that is undefined, zero, negative, overflowing, or tainted – which can lead to an invalid memory extent and potential runtime errors.