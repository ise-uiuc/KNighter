## Bug Pattern

Subtracting from an iov_iter’s byte count using a value computed with a rounded-up (block-aligned) length without first ensuring the subtraction is non-negative, causing unsigned underflow. Concretely:

- Compute a “shorten” amount as: shorten = iov_iter_count(iter) - round_up(valid_len, block_size)
- Then do: iter->count -= shorten;

If round_up(valid_len, block_size) > iov_iter_count(iter), shorten wraps (size_t) and iter->count underflows, corrupting the request size. The fix is to clamp or check: if (shorten >= iter->count) shorten = 0 (or otherwise ensure the subtraction cannot exceed iter->count).
