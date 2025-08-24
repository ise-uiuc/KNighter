## Bug Pattern

Returning an uninitialized local status variable.

Pattern details:
- A function declares a local int ret; intended as the return value.
- ret is only assigned inside conditional/error paths (e.g., within loop bodies or before goto error labels).
- There exist control flows where those paths are not taken (e.g., loop doesn’t iterate, no errors occur), yet the function returns ret (often via a common out: label).
- This leads to returning an indeterminate (uninitialized) value.

Example shape:
int ret;          // not initialized
...
if (error)
    { ret = -EFOO; goto out; }
...
out:
return ret;       // ret may be uninitialized if no assignment occurred

Fix: initialize ret (e.g., ret = 0) at declaration to ensure a defined success return on paths that don’t set it.
