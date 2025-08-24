## Bug Pattern

Copying a stack-allocated struct with implicit padding/holes to user space (e.g., via nla_put(..., sizeof(struct), &obj)) after only partially initializing its fields. The uninitialized padding bytes leak kernel stack data. Root cause: not zero-initializing a padded struct before exporting it.
