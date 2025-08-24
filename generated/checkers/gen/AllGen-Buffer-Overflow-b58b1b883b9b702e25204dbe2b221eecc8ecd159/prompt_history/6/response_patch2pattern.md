## Bug Pattern

Computing a reduction length with unsigned arithmetic as:
shorten = iov_iter_count(iter) - round_up(request_len, block_size);
and then doing:
iter->count -= shorten;
without verifying that round_up(request_len, block_size) <= iov_iter_count(iter).

Because size_t is unsigned, if the rounded-up size exceeds the current iterator length, the subtraction underflows, producing a huge “shorten” and causing iter->count to wrap/underflow to a bogus large value.
