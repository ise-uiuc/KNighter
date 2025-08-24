## Bug Pattern

Copying setsockopt data from user space without validating optlen against the expected object size.

Typical instances:
- Calling copy_from_sockptr(&obj, optval, sizeof(obj)) without first ensuring optlen >= sizeof(obj), leading to out-of-bounds reads when the user supplies a shorter buffer.
- Using a partial copy (e.g., len = min(sizeof(obj), optlen); copy_from_sockptr(&obj, optval, len)) which allows short input and leaves obj partially initialized, risking misuse of uninitialized fields.

Correct pattern is to use a helper that checks optlen (e.g., bt_copy_from_sockptr(&obj, sizeof(obj), optval, optlen)) or explicitly validate optlen before copying.
