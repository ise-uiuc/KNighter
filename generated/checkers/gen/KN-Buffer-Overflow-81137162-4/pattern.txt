## Bug Pattern

Using an unbounded string copy (strcpy) to copy a variable-length source string into a fixed-size struct field (e.g., name[8]) without validating or limiting the length, causing potential buffer overflow when the source exceeds the destination size.
