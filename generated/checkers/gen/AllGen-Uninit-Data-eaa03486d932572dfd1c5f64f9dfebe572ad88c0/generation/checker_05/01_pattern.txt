## Bug Pattern

A function returns a local status variable (commonly named "ret") that is declared but not initialized, and is only assigned in some error branches. On success paths (including when loops don't execute or no errors occur), the function reaches a common exit and returns this uninitialized variable.

Example pattern:
int ret;  // not initialized
...
if (error)
    { ret = -ENOMEM; goto out; }
...
out:
return ret;  // ret may be uninitialized on success

This leads to undefined return values and potential use of uninitialized memory.
