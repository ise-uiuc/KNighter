## Bug Pattern

Publishing a newly created kernel object to a user-visible ID table (e.g., via xa_alloc()/idr_alloc()) before the object is fully initialized and before the ioctl returns. Because IDs are predictable, a malicious user can issue a destroy operation on the guessed ID while the create ioctl still uses the object, leading to a use-after-free. The fix is to perform all initialization and take required references first, and make the ID allocation/publication the last step.
