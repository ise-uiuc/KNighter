## Bug Pattern

Copying user-provided data into a fixed-size buffer using copy_from_user() with the unvalidated user length (nbytes), i.e., not bounding the copy by sizeof(buffer) - 1. This can overflow the stack/local buffer.

Pattern example:
- char buf[64];
- if (copy_from_user(buf, user_ptr, nbytes)) return -EFAULT;  // nbytes not clamped to sizeof(buf)-1

Correct pattern:
- size_t len = min(nbytes, sizeof(buf) - 1);
- if (copy_from_user(buf, user_ptr, len)) return -EFAULT;
- return len;
