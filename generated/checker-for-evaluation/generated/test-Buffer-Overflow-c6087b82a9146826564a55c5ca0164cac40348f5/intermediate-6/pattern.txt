## Bug Pattern

Using copy_from_user() to copy data from user space into a fixed-size buffer without validating or limiting the number of bytes to be copied against the buffer's capacity. This unchecked copy can lead to a buffer overflow if the user-supplied nbytes exceeds the available space in the destination buffer.