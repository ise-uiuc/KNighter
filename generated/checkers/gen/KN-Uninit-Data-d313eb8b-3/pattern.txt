## Bug Pattern

Copying a stack-allocated struct to user space (e.g., via nla_put(..., sizeof(struct), &obj)) after only partially initializing its fields, leaving structure padding/holes uninitialized. Because designated/field-by-field initialization does not zero padding, sizeof(struct) copies include uninitialized bytes, causing a kernel info leak.

Example:
struct S { u32 a; u8 b; /* padding */ u32 c; };
struct S s = { .a = x, .c = y };  // padding remains uninitialized
nla_put(skb, ATTR, sizeof(s), &s);  // leaks padding

Fix: zero the struct first (memset(&s, 0, sizeof(s)) or use kzalloc for heap objects) before filling fields.
