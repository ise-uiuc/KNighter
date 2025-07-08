## Bug Pattern

Using an unsafe string copy function (strcpy) to copy data into a fixed-size buffer without performing bounds checking. This can lead to a buffer overflow when the source string exceeds the destination buffer's allocated size.