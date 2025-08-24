## Bug Pattern

Computing a shrink amount as an unsigned difference between the current I/O length and a block-aligned length, and then subtracting it from iter->count without verifying that the aligned length is not larger than the current length. Specifically:
- shorten = iov_iter_count(iter) - round_up(len, block_size) uses size_t
- If round_up(len, block_size) > iov_iter_count(iter), the subtraction underflows
- Iter->count -= shorten then massively underflows, corrupting iterator length

This occurs when aligning a sub-block request (e.g., 512B) to a larger filesystem block (e.g., 4K) without bounding the shrinkage.
