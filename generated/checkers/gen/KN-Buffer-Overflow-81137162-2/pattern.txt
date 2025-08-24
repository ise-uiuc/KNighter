## Bug Pattern

Using an unbounded string copy (strcpy) to copy a potentially longer source string into a fixed-size destination buffer inside a struct, leading to buffer overflow. For example:

char dest[8];
strcpy(dest, src);  // src length may exceed sizeof(dest)

In the patch: copying hdev->name into di.name (size 8) with strcpy, without length checking.
