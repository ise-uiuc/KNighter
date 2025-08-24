## Bug Pattern

Plain (non-atomic) read/modify/write of a per-CPU counter that is also accessed from other CPUs (via per_cpu_ptr(..., cpu)), i.e., cross-CPU access to per-CPU data without synchronization or READ_ONCE/WRITE_ONCE. Specifically:
- Fast path does: statc->stats_updates += abs(val); if (statc->stats_updates < ...) ...
- Flush path concurrently reads/zeros: statc->stats_updates = 0;

This unsynchronized concurrent access causes data races/torn reads/writes. The fix snapshots with READ_ONCE, updates with WRITE_ONCE, and uses the snapshot for subsequent logic.
