## Bug Pattern

Using an unbounded string copy (e.g., strcpy) to copy a potentially long string into a fixed-size struct field, without enforcing the destination buffer’s size, leading to buffer overflow. Example:

char dest[8];            // fixed-size struct field
const char *src = hdev->name; // variable-length string
strcpy(dest, src);       // overflows if src >= 8

Correct pattern: strscpy(dest, src, sizeof(dest)) to bound and NUL-terminate.
