## Bug Pattern

Copying a potentially longer string into a fixed-size buffer using an unbounded API (e.g., strcpy) without checking or limiting the length of the source, causing possible buffer overflow. Concretely:

char dest[8];
strcpy(dest, src);  // src may exceed sizeof(dest)

The correct pattern is to use a bounded copy with the destination size (e.g., strscpy(dest, src, sizeof(dest))).
