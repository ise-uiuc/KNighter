## Bug Pattern

The bug pattern here is failing to fully initialize a structure that contains padding or holes (unused bytes) before copying it to user space. Using a partial aggregate initializer leaves these gaps uninitialized, potentially leaking kernel stack data. The fix is to zero the structure (e.g., with memset) before assigning specific fields.