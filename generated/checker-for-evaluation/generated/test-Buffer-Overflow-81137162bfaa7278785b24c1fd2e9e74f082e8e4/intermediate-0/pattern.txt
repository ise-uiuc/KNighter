## Bug Pattern

Using an unbounded string copy function (strcpy) to copy data into a fixed-size buffer, which can lead to a buffer overflow if the source string exceeds the destination buffer's size.