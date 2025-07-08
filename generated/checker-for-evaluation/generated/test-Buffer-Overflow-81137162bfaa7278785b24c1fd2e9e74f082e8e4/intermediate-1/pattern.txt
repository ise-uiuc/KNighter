## Bug Pattern

Using unbounded string copy (via strcpy) to a fixed-size buffer can lead to buffer overflows when the source string is larger than the destination buffer's capacity.