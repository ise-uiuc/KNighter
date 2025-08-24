## Bug Pattern

Using an unbounded string copy (strcpy) to write a potentially longer source string (e.g., hdev->name) into a fixed-size destination buffer in a struct (e.g., di.name[8]) without checking or limiting the length, leading to buffer overflow. The correct approach is a bounded copy such as strscpy(dest, src, sizeof(dest)).
