## Bug Pattern

Using unsafe string copy functions like strcpy to copy data from a potentially longer source into a fixed-size destination buffer without bounds checking. This can lead to buffer overflows when the source string exceeds the fixed buffer size.