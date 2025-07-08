## Bug Pattern

The bug pattern is copying user-supplied data into a fixed-size buffer without properly limiting the number of bytes copied. Without bounds checking, using copy_from_user() with nbytes that exceeds the buffer size can lead to a buffer overflow, potentially overwriting adjacent memory.