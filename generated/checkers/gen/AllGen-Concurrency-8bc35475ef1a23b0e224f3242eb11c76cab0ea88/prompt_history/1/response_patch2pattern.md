## Bug Pattern

Premature, unconditional read of a shared/concurrently-updated field before checking the condition that establishes exclusive access/serialization.

Concretely:
- Code reads a non-atomic shared state (e.g., data = *work_data_bits(work)) outside of or prior to the guard (e.g., from_cancel) that guarantees ownership/safety.
- Even if the value is only used under the guard, the mere unconditional read can race with writers and trigger data-race detectors (KCSAN).
- Correct pattern is to move the read inside the conditional that proves exclusivity, or otherwise synchronize the read.
