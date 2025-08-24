## Bug Pattern

Loop iterates up to the last valid index of an array while accessing the next element (i + 1) without a bound check, causing an off-by-one out-of-bounds access.

Pattern example:
- Given an array of length N:
  - for (i = 0; i < N; ++i) {
      ...
      use(arr[i + 1]); // OOB when i == N - 1
    }

Correct patterns:
- for (i = 0; i + 1 < N; ++i) { ... use(arr[i + 1]); ... }
- or guard the access: if (i + 1 < N) use(arr[i + 1]);
