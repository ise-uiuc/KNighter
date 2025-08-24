## Bug Pattern

Copying user-provided data into a fixed-size buffer without bounding the copy size to the buffer capacity and without guaranteeing NUL-termination before string parsing. Concretely:

char buf[64];
...
/* nbytes is user-controlled and may exceed sizeof(buf) */
copy_from_user(buf, user_ptr, nbytes);   // potential stack buffer overflow
...
strncmp(buf, "reset", strlen("reset"));  // treats buf as a string without ensured NUL

The correct pattern is to cap the copy to min(nbytes, sizeof(buf) - 1) and preserve a trailing NUL.
