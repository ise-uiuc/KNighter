## Bug Pattern

Copying a user-provided length into a fixed-size kernel buffer without bounding the copy to the buffer size, i.e., using copy_from_user(buf, user, nbytes) where nbytes can exceed sizeof(buf). This occurs in debugfs write handlers that parse string commands into a small stack buffer and do not cap nbytes (and leave no room for a terminating NUL), leading to potential stack buffer overflow.

Example pattern:
char buf[64];
/* nbytes is user-controlled; no size cap -> overflow risk */
if (copy_from_user(buf, user_ptr, nbytes))
    return -EFAULT;
/* then treat buf as a string (e.g., strncmp) without guaranteed NUL */
