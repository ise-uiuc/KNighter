## Bug Pattern

Iterating over two parallel arrays with the same index while using the length/limit of the larger array as the loop bound, and then indexing into the smaller array without an additional bound check. Concretely:

for (i = 0; i < SIZE_A; i++) {   // SIZE_A > SIZE_B
    if (A[i] == key)
        return B[i];             // out-of-bounds when i >= SIZE_B
}

Here, A has SIZE_A elements and B has SIZE_B elements; the loop uses SIZE_A but also accesses B[i], causing a buffer overflow when i reaches SIZE_B..
