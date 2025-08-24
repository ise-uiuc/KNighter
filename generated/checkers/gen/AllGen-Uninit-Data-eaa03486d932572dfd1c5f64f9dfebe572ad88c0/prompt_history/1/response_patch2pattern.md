## Bug Pattern

Declaring a status/return variable (e.g., `int ret;`) without initialization and only assigning it inside conditional/error paths (often within loops), then exiting through a common label (e.g., `goto out; ... return ret;`) or returning it directly. If no condition assigns `ret` (e.g., loop doesn’t iterate or no error occurs), the function returns an uninitialized value.

Example pattern:
- `int ret;`
- `if (error) { ret = -ENOMEM; goto out; }`
- `...`
- `out: return ret;`  // ret may be uninitialized if no error path taken

Correct pattern: initialize `ret` to a success value (e.g., `int ret = 0;`) at declaration.
