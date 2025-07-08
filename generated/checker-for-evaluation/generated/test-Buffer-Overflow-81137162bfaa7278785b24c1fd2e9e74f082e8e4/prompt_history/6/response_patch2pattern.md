## Bug Pattern

Using an unchecked string copy (strcpy) to copy data into a fixed-size buffer without ensuring that the source string fits, which can cause a buffer overflow if the source exceeds the destination buffer's capacity.