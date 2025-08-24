## Bug Pattern

Reading a shared/concurrently-updated field before verifying the condition that guarantees safe/exclusive access. Specifically, an unconditional read of work->data (which other CPUs may modify) occurs prior to checking from_cancel; even if the value is not used when the guard is false, the mere read races with writers and triggers KCSAN. The correct pattern is to first check the guard that ensures exclusive/safe access and only then read the shared field (or otherwise use atomic/READ_ONCE if required).
