## Bug Pattern

Publishing a newly created kernel object into a user-visible ID map (e.g., via xa_alloc/idr) before the object is fully initialized and before the creator has secured its own stable reference. This early exposure lets untrusted users issue operations (e.g., destroy) on a predictable/guessable ID while the create path still uses the object, leading to a race and use-after-free in the creator path.
