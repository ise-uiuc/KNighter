## Bug Pattern

Partially initializing a stack-allocated structure that contains implicit padding (holes) without zeroing out the entire structure, leading to uninitialized memory being copied to user space and causing a kernel information leak.