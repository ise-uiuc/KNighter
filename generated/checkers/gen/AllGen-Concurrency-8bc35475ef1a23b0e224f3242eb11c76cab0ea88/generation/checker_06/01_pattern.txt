## Bug Pattern

Speculative, unguarded read of a concurrently modified field before checking the condition that makes the read safe.

Pattern example:
- Read shared state first: data = *shared_bits;
- Then test the guard that guarantees exclusive ownership: if (from_cancel) { use(data); }
- Even if data isn’t used when the guard is false, the initial read can race with writers and trigger KCSAN.

Correct pattern:
- Check the guard (which ensures safe access) first, and only then read the shared field: if (from_cancel) { data = *shared_bits; ... }
