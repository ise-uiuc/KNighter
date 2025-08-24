## Bug Pattern

Computing a reduction amount as an unsigned difference between the current I/O length and a rounded-up (to block size) target length, then subtracting it from iter->count without first ensuring the difference is non-negative:

shorten = iov_iter_count(iter) - round_up(valid_len, block_size);
iter->count -= shorten;

If round_up(valid_len, block_size) > iov_iter_count(iter), the unsigned subtraction underflows, causing iter->count to wrap and become invalidly large.
