## Bug Pattern

Returning an uninitialized local status variable:
- A local int (ret) is declared without initialization and only assigned in some error branches inside loops/goto paths.
- If no error occurs or the loop is not entered, control reaches a common return path that returns ret, which remains uninitialized.
- This yields an undefined/garbage return value instead of 0 (success).
