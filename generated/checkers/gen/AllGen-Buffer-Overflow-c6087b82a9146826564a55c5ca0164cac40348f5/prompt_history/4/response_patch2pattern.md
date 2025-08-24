## Bug Pattern

Copying user-provided data into a fixed-size stack buffer using copy_from_user() without bounding the length by the buffer size (e.g., using nbytes directly). This allows nbytes (controlled by userspace) to exceed sizeof(buffer), causing a stack buffer overflow. The safe pattern is to cap the length to min(nbytes, sizeof(buffer) - 1) before copying, especially when the buffer is later treated as a string.
