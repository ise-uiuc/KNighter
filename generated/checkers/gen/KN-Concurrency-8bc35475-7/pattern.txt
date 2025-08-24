## Bug Pattern

Speculative/early read of a concurrently modified shared field before verifying the condition that makes the access safe.

Concretely: reading work->data (via work_data_bits(work)) unconditionally, without locking or READ_ONCE, even though that read is only valid when from_cancel is true (which guarantees exclusive ownership). This unconditional read can race with concurrent writers and trigger KCSAN, even if the value is later unused when the condition is false. The correct pattern is to first check the guarding condition that provides synchronization (e.g., from_cancel) and only then access the shared field.
