## Bug Pattern

Using an unbounded string copy (strcpy) to copy a string into a fixed-size buffer, which can lead to a buffer overflow if the source string is larger than the destination buffer. The fix replaces strcpy with a bounded copy (strscpy) that respects the destination buffer size.