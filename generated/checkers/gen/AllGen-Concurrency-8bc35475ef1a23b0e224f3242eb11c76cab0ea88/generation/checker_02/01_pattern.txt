## Bug Pattern

Unconditional speculative read of a shared, concurrently updated field before validating the guard that establishes safe/exclusive access. Specifically, reading work->data outside the from_cancel check (i.e., before confirming the cancellation path that guarantees exclusive ownership) causes an unsynchronized access/data race, even if the value is later unused when the guard is false. The fix moves the read under the guarding condition.
