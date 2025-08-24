## Bug Pattern

Publishing a partially initialized kernel object to a user-visible ID map (e.g., inserting into an XArray/IDR via xa_alloc) before the create path is finished and before securing necessary references. This early exposure, combined with predictable IDs, allows another thread to look up and destroy the object via its ID while the creator still uses it, leading to a use-after-free.
