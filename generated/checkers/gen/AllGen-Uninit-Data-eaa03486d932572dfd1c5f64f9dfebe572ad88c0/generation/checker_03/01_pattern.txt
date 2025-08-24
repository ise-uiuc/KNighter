## Bug Pattern

Returning an uninitialized status variable due to cleanup/exit paths that don’t assign it on all control flows.

Typical form:
- A local int (e.g., ret) is declared without initialization.
- It is only set in some branches (e.g., error paths or when work is done inside a loop).
- The function exits via a common label (goto out; … out:) and returns ret, but if no branch assigned ret (e.g., loop does no work, or no errors occur), ret remains uninitialized.

Example pattern:
int ret;            // not initialized
...
if (cond1) {
    ret = -ENOMEM;
    goto out;
}
...
// no assignment to ret on success/no-op paths
out:
return ret;         // ret may be uninitialized
