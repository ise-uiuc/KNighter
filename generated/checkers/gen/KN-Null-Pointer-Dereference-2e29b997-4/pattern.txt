## Bug Pattern

Incorrect NULL-check after allocation: the code allocates one pointer but checks a different pointer for NULL.

Example pattern:
ptrA = kzalloc(size, GFP_KERNEL);
if (!ptrB)  // wrong pointer checked
    return -ENOMEM;

In the patch, after allocating dst->thread.sve_state, the code mistakenly checks dst->thread.za_state instead of dst->thread.sve_state, causing allocation failures for sve_state to be missed.
