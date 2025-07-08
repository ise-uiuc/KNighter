## Bug Pattern

Using an unsafe string copy function (strcpy) to copy a possibly oversized string into a fixed-size buffer without bounds checking, which can lead to a buffer overflow.