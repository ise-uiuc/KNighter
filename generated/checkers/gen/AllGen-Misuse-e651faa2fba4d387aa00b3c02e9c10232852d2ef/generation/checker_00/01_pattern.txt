## Bug Pattern

Manually computing the byte size for duplicating a user-provided array and passing it to memdup_user()/vmemdup_user(), e.g.:

- ptr = memdup_user(userp, count * sizeof(*userp));
- ptr = vmemdup_user(userp, array_size(count, sizeof(*userp)));

This risks integer overflow in the size calculation. In particular, array_size() returns SIZE_MAX on overflow, but vmemdup_user() does not treat SIZE_MAX as an overflow indicator and will attempt a huge allocation instead of failing cleanly. The correct pattern is to use memdup_array_user()/vmemdup_array_user(), which perform checked multiplication and properly detect/handle overflows.
