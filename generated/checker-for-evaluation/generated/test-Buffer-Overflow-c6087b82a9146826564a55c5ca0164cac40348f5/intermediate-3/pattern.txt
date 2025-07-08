## Bug Pattern

Using an unchecked user-provided byte count in copy_from_user(), which can lead to a buffer overflow by copying more data than the capacity of the fixed-size stack buffer. The code fails to restrict the number of bytes copied to the actual size of the destination buffer, allowing potential overflow when nbytes exceeds the buffer's size.