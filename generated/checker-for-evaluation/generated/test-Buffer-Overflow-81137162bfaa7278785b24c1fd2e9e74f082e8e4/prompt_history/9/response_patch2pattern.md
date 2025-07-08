## Bug Pattern

Using an unsafe string copy function (strcpy) to copy a source string into a fixed-size buffer, without enforcing boundary checks. This pattern can lead to a buffer overflow if the source string exceeds the allocated size of the destination buffer.