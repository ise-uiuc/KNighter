## Bug Pattern

Using an unbounded string copy (e.g., strcpy) to copy a runtime string into a fixed-size buffer (struct member) without enforcing the destination’s length, allowing overflow when the source is longer than the destination.

Example pattern:
- char dest[FIXED_SIZE];  // e.g., name[8] in a struct
- strcpy(dest, src);      // src length may exceed FIXED_SIZE, causing overflow

Correct approach: use a bounded copy (e.g., strscpy(dest, src, sizeof(dest))).
