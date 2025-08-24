## Bug Pattern

Returning an uninitialized status variable:
- A local int ret is declared but not initialized.
- ret is only assigned inside conditional/loop error paths.
- The function exits via a common return path (or goto label) that returns ret even when no assignment has occurred.

Typical code shape:
int ret;   // not initialized
...
if (error)
    ret = -EINVAL;
...
return ret;  // may return garbage if no error path taken

Fix: initialize ret to a known success value (e.g., 0) at declaration.
