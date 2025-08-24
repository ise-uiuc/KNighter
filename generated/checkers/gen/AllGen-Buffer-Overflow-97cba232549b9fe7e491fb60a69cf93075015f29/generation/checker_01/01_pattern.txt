## Bug Pattern

Off-by-one array iteration when accessing a look-ahead element:
looping with i < size while dereferencing arr[i + 1] inside the loop. This makes the last iteration access arr[size], which is out of bounds. Correct pattern requires bounding the loop by size - 1 when using arr[i + 1], e.g.:

for (i = 0; i < size - 1; ++i) {
    use(arr[i]);
    use(arr[i + 1]);
}
