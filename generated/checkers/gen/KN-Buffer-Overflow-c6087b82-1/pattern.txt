## Bug Pattern

Copying user-provided data into a fixed-size buffer with copy_from_user() using the untrusted nbytes (write count) without clamping it to the destination buffer size (e.g., sizeof(buf) - 1). This allows a user to pass a larger nbytes than the buffer can hold, causing a stack buffer overflow in debugfs/sysfs write handlers.
