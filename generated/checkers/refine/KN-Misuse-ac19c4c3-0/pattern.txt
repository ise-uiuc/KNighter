## Bug Pattern

Manually computing the byte count for a memory operation as sizeof(element) * count where count can come from userspace, without overflow checking. This open-coded multiplication can overflow size_t and wrap around, causing copy_from_user (or similar APIs) to operate on an incorrect size. The correct pattern is to use overflow-checked helpers like array_size(element_size, count) (or struct_size) for size calculations passed to copy/alloc functions.
