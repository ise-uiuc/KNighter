## Bug Pattern

Indexing two “parallel” arrays with the same loop index while bounding the loop by the size of only one array, where the other array is smaller. Concretely:

for (i = 0; i < SIZE_A; i++) {
    if (A[i] == key)
        return B[i];  // but SIZE_B < SIZE_A
}

Here, using i derived from SIZE_A to index B causes out-of-bounds access when SIZE_A > SIZE_B (e.g., iterating over SocVoltage but reading DcfClocks with fewer entries).
