## Bug Pattern

Using unbounded user-provided length (nbytes) in a copy_from_user() call to copy data into a fixed-size buffer without limiting the number of bytes copied, which can lead to a potential buffer overflow.