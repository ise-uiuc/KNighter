## Bug Pattern

Copying user-provided data into a fixed-size buffer using copy_from_user() with an unbounded, user-controlled length (nbytes), i.e.:

char buf[64];
if (copy_from_user(buf, user_buf, nbytes))  // nbytes may exceed sizeof(buf)

This allows a stack buffer overflow. The correct pattern is to clamp the copy length to the buffer size (typically sizeof(buf) - 1 if later treated as a string) and use that bounded length for both copying and the return value.
