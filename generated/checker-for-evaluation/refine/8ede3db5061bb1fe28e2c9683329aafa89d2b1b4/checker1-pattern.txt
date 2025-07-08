## Bug Pattern

Casting an unsigned value (size_t) to a signed integer (int) before performing an overflow check. This misrepresentation of the value may turn a large unsigned value into a negative number, causing the overflow detection (via check_add_overflow) to fail since negative numbers do not trigger the intended overflow behavior, which can result in an integer underflow.