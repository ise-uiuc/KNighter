## Bug Pattern

Plain (non-atomic) read/modify/write of a per-CPU field that is also accessed from other CPUs.

Concretely:
- One CPU does: statc->stats_updates += x; and later statc->stats_updates = 0;
- Another CPU may concurrently read/write the same per-CPU field during a flush.
- Because the per-CPU variable is remotely accessed, using ordinary loads/stores causes a data race (possible torn/partial read/writes).

Correct pattern is to use READ_ONCE/WRITE_ONCE (or atomics) for all cross-CPU accesses to such fields to avoid racy increments/clears.
