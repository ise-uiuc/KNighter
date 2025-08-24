## Bug Pattern

Using check_add_overflow() with a narrower destination type (int) while downcasting size-related operands (size_t/sizeof) to int, causing truncation/sign-change. Large size_t values can become negative when cast to int, making the addition appear non-overflowing in int and thus bypassing the overflow check. The check must be performed in the widest relevant type (e.g., size_t) without lossy casts.
