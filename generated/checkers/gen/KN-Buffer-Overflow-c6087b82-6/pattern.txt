## Bug Pattern

Copying user-provided data into a fixed-size buffer without bounding the copy length by the buffer size:

- Pattern:
  - Fixed-size buffer on stack/heap:
    - char buf[64];
  - Untrusted length from userspace (e.g., write(2) nbytes) used directly:
    - copy_from_user(buf, user_ptr, nbytes);
  - No clamp like min(nbytes, sizeof(buf) - 1) before copy.
  - Often also followed by treating buf as a string and/or returning nbytes.

This leads to potential buffer overflow (and non-NUL-terminated strings).
