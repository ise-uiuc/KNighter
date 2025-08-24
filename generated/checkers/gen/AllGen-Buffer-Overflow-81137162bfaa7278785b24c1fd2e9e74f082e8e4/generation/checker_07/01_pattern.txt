## Bug Pattern

Using an unbounded string copy (strcpy) to copy a variable-length source into a fixed-size destination buffer within a struct, without checking the destination size. Example: strcpy(di.name, hdev->name) where di.name is a small fixed array (name[8]) and hdev->name may be longer, causing buffer overflow. The correct pattern is to use a bounded copy (e.g., strscpy(dest, src, sizeof(dest))).
