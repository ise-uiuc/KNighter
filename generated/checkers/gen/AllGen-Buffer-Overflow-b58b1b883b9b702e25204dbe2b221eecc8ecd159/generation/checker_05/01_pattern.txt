## Bug Pattern

Subtracting an alignment-rounded size from an unsigned length without bounds checking:
- The code rounds up a desired I/O length to the filesystem block size (round_up(ret, block_bytes(...))) and then computes shorten = iov_iter_count(iter) - rounded_up_len using size_t.
- If the rounded-up length exceeds the iterator’s total length, this subtraction underflows (wraps to a huge size), and applying iter->count -= shorten underflows iter->count, corrupting the iterator and causing crashes.
- Root cause: using unsigned arithmetic to shrink a count based on a rounded-up value without first verifying that the rounded-up value is <= the original count (or clamping the result to zero).
