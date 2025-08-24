## Bug Pattern

Unconditional speculative read of a concurrently updated shared field before checking the gating condition that makes the read safe.

Concretely:
- Reading work->data (a field updated by other CPUs) without synchronization and before verifying from_cancel, even though the value is only needed when from_cancel is true.
- This unnecessary, unsynchronized read can race with writers (e.g., insert_wq_barrier updating work->data), triggering KCSAN data-race reports.

Pattern in code:
unsigned long data = *work_data_bits(work);
if (from_cancel && use(data)) { ... }

Correct approach: First check the gating condition (from_cancel), then read the shared field only when needed.
