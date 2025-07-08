## Bug Pattern

An off-by-one error caused by iterating the array to its full length while accessing elements with an offset (i+1) without reducing the loop bound. This pattern leads to accessing an element beyond the allocated array and results in a buffer overflow.