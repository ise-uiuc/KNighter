## Bug Pattern

The bug pattern is an out-of-bound array access due to an off-by-one error in the loop condition. The code iterates over an array and then accesses the next element (i + 1) without ensuring that it is within the valid range. This pattern risks buffer overflow when the loop reaches the last valid index and accesses an element beyond the array's bounds.