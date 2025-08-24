## Bug Pattern

Post-allocation NULL check on the wrong pointer.

Example pattern:
ptr_alloc = kzalloc(size, GFP_KERNEL);
if (!ptr_other)
    return -ENOMEM;

Here, memory is allocated into ptr_alloc but the error check tests ptr_other instead of ptr_alloc, so allocation failures for ptr_alloc go undetected and can lead to later NULL dereference or invariant violations.
