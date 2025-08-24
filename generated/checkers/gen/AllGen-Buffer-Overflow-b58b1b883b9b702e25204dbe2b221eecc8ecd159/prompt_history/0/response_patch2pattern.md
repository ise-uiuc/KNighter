## Bug Pattern

Computing a decrement as (available_len - round_up(request_len, align)) using unsigned sizes and then subtracting it from a length without verifying that round_up(request_len, align) <= available_len. If the rounded-up length exceeds the available length, the unsigned subtraction underflows, and the subsequent “len -= shorten;” wraps the length to a huge value.

Example:
- size_t shorten = iov_iter_count(iter) - round_up(ret, block_bytes);
- iter->count -= shorten;  // underflows if round_up(ret, block_bytes) > iov_iter_count(iter)

Root cause: Missing bound check before subtracting an alignment-inflated length from an unsigned length, leading to size_t underflow.
