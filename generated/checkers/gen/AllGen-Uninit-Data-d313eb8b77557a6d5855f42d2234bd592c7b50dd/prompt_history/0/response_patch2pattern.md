## Bug Pattern

Partially initialized stack struct (via designated initializers or field-by-field assignments) is copied to user space using sizeof(struct), leaking uninitialized padding bytes.

Example pattern:
struct S { u32 index; u32 refcnt; u32 bindcnt; /* padding/hole exists */ };
struct S s = { .index = idx, .refcnt = r, .bindcnt = b };  // only members set; padding uninitialized
nla_put(skb, ATTR, sizeof(s), &s);  // copies padding to user (info leak)

Root cause: struct contains padding and the code does not fully zero the object before exporting it; copying sizeof(struct) includes those uninitialized padding bytes.
