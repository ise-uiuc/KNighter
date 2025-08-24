## Bug Pattern

Returning an uninitialized status variable.

Pattern characteristics:
- A local variable (commonly named ret) is declared without initialization:
  int ret;
- ret is only assigned inside conditional blocks (e.g., error paths inside loops or ifs), and not on the normal/success path.
- The function ends with return ret; (possibly via labels/goto), so if none of the conditional assignments execute (e.g., loop doesn’t iterate), ret is read uninitialized.

Fix: Initialize ret to a known success value (typically 0) at declaration:
int ret = 0;
