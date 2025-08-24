## Bug Pattern

Copying a stack-allocated struct to user space with sizeof(struct) after only partially initializing its fields, leaving alignment padding/holes uninitialized. Specifically:
- A struct with padding (e.g., tc_skbmod) is created on the stack.
- Only selected fields are set via designated initializers or assignments.
- The entire struct (including padding) is exported with nla_put/copy_to_user, leaking uninitialized stack bytes.

Fix: fully initialize the struct (e.g., memset(&s, 0, sizeof(s)) or struct S s = {0};) before copying it to user space.
