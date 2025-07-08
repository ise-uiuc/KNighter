## Bug Pattern

Copying a partially initialized structure that contains implicit padding. In this case, a stack-allocated structure is not zeroed out before its fields are set, leaving uninitialized bytes (a hole) that are later copied to user space, potentially leaking sensitive kernel stack data.