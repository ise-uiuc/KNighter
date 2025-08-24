## Bug Pattern

Partially initialized stack struct (with padding/holes) is copied to user space with sizeof(struct), leaking uninitialized bytes. Example pattern:

- Define and set only some fields of a struct on the stack (e.g., via designated initializer or selective assignments).
- The struct has implicit padding/holes due to alignment.
- Pass the entire struct to user (e.g., nla_put(..., sizeof(s), &s) or copy_to_user(..., &s, sizeof(s))) without zeroing it first.

Fix is to zero-initialize the whole struct (e.g., memset(&s, 0, sizeof(s))) before filling fields, or otherwise ensure all bytes are initialized.
