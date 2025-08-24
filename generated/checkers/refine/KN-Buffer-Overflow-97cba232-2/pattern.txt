## Bug Pattern

Off-by-one array access caused by iterating to the last valid index while also accessing the next element:

for (i = 0; i < N; i++) {
    use(a[i]);
    use(a[i + 1]); // out-of-bounds when i == N - 1
}

Root cause: a loop uses condition i < N, but the body reads a[i + 1] without ensuring i + 1 < N. The fix is to bound the loop to i < N - 1 (or guard the a[i + 1] access).
