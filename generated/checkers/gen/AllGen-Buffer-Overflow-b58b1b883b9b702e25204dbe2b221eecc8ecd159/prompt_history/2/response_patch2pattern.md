## Bug Pattern

Adjusting an iov_iter’s byte count using unsigned size arithmetic without bounding the decrement, specifically:

- Compute a “shrink” amount as (available_count - round_up(request_len, block_size)).
- Store it in a size_t and subtract it from iter->count.
- If round_up(request_len, block_size) > available_count, the subtraction underflows (size_t), and iter->count becomes a huge value.

In code:
size_t shorten = iov_iter_count(iter) - round_up(ret, block_bytes(c));
iter->count -= shorten;  // underflows if round_up(...) > iov_iter_count(iter)

Root cause: missing check/cap ensuring the rounded-up length does not exceed the iterator’s total length before subtracting, leading to unsigned underflow of iter->count.
