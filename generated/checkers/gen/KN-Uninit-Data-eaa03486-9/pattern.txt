## Bug Pattern

Returning an uninitialized status variable.

Pattern:
- A local variable (e.g., `int ret;`) is declared to carry the return status.
- It is only assigned inside conditional/error branches or within loops.
- On valid/no-op paths (e.g., when no iterations or no errors occur), control reaches a common cleanup/return label and returns `ret` without ever initializing it.

Example shape:
int ret;           // not initialized
...
if (cond) {
    ret = -ERR;    // only set in some branches
    goto out;
}
...
out:
return ret;        // may return garbage if no branch set ret

Fix: initialize `ret` (e.g., `int ret = 0;`) or ensure it is assigned on all paths before return.
