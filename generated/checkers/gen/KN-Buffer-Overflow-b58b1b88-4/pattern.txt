## Bug Pattern

Computing a size_t “shorten” as the unsigned difference between the current iov_iter length and a rounded-up (block-aligned) length, and then subtracting it from iter->count without verifying that the rounded-up length is not larger than the available length. This causes unsigned underflow and wraps iter->count to a huge value.

Pattern:
- need = round_up(valid_len, block_size)
- avail = iov_iter_count(iter)
- shorten = avail - need;        // underflows if need > avail
- iter->count -= shorten;        // uses wrapped value

Correct pattern must clamp/check:
if (need > avail) shorten = 0; or equivalently if (shorten >= iter->count) shorten = 0.
