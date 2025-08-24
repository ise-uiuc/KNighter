## Bug Pattern

Copying setsockopt() user data from a sockptr without validating optlen against the expected size:

- Using copy_from_sockptr(&dst, optval, sizeof(dst)) with no check that optlen >= sizeof(dst), causing out-of-bounds reads when the user provides a shorter buffer.
- For structs, copying only min(sizeof(struct), optlen) bytes and accepting partial input instead of rejecting short buffers, which can lead to inconsistencies or use of partially initialized data.

Correct pattern: ensure optlen is sufficient (e.g., via a helper like bt_copy_from_sockptr(dst, sizeof(*dst), optval, optlen) or explicit optlen >= sizeof checks) before copying.
