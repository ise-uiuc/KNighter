## Bug Pattern

Creating a stack-allocated struct and initializing only some fields (e.g., via a designated initializer), then copying the entire struct (sizeof(struct)) to user space (e.g., via nla_put/copy_to_user). Because stack padding/holes and any untouched fields remain uninitialized, this leaks kernel stack data.

Example pattern:
struct S s = { .a = val_a, .b = val_b };  // not all fields/padding initialized
... // maybe set a few more fields
nla_put(skb, ATTR, sizeof(s), &s);        // copies uninitialized bytes too

Correct pattern is to zero-initialize the struct first (e.g., memset(&s, 0, sizeof(s)) or use kzalloc) before setting fields.
