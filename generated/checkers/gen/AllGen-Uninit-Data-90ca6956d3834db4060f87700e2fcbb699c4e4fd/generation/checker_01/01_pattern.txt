## Bug Pattern

Declaring auto-cleanup pointers (annotated with __free(kfree)) without initializing them to NULL, and then returning or leaving scope before assigning them a valid value. This causes the cleanup handler to call kfree() on an uninitialized/garbage pointer at scope exit.

Example pattern:
struct foo *p __free(kfree);  // not initialized
if (error)
    return -EINVAL;           // cleanup runs: kfree(p) on uninitialized value

Fix: Always initialize such auto-cleanup pointers to NULL at declaration.
