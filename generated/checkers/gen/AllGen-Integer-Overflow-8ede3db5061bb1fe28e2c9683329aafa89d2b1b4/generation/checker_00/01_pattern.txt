## Bug Pattern

Casting a size-related unsigned value (e.g., size_t) to a narrower signed type (e.g., int) before an overflow check with check_add_overflow(), where the result pointer is of the signed narrower type. This can turn large positive inputs into negative values that fit in int, causing the overflow check to falsely report “no overflow.”

Example:
- Bad: check_add_overflow(hdr, (int)controllen, &hdr);
- Good: avoid narrowing cast; do not convert size_t to int before the check.
