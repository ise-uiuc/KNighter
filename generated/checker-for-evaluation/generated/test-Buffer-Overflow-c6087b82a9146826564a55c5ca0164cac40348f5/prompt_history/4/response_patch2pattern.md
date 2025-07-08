## Bug Pattern

Using copy_from_user() without limiting the number of bytes copied to the size of the destination buffer. This leads to a potential buffer overflow if the user-supplied nbytes exceeds the fixed buffer size, allowing an overflow when writing data into the kernel buffer.