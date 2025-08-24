## Bug Pattern

Stack-allocated struct with padding/holes is only partially initialized, then the entire struct (sizeof(struct)) is copied to user space (e.g., via nla_put/copy_to_user). The uninitialized padding bytes get leaked.

Pattern example:
- struct S has implicit padding
- Code initializes only some members
- Calls nla_put(..., sizeof(S), &s) (or equivalent) without zeroing s first

Root cause: not zero-initializing a struct with padding before exporting it, leading to kernel-infoleak through uninitialized padding bytes.
