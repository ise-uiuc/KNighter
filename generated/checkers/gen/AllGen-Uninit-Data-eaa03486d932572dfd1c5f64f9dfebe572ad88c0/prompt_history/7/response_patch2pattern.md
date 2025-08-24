## Bug Pattern

Returning an uninitialized status variable:
- A local int (e.g., ret) is declared to carry the function’s return code but is not initialized.
- It is only assigned within conditional/error paths (inside loops or branches).
- If those paths are not taken (e.g., loop doesn’t run or no errors occur), the function reaches a common return label and returns the uninitialized variable, yielding an undefined success/error code.

Typical shape:
int ret;   // not initialized
...
if (cond) { ret = -ERR; goto out; }
...
out:
return ret;  // may return garbage if ret was never set

Correct pattern: initialize ret = 0 (success) at declaration.
