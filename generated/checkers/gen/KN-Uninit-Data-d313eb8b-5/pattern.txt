## Bug Pattern

Copying a stack-allocated struct to user space using sizeof(struct) (e.g., via nla_put/copy_to_user) without first zeroing the entire struct, when the struct contains padding/holes. Only assigning selected fields (even with designated initializers) leaves padding bytes uninitialized, causing a kernel information leak when the raw struct memory is exported.

Example:
struct foo s;            // has padding
s.a = ...; s.b = ...;    // fields set, padding untouched
nla_put(skb, ATTR, sizeof(s), &s);  // leaks uninitialized padding bytes

Correct pattern: memset(&s, 0, sizeof(s)) (or kzalloc for heap) before filling fields.
