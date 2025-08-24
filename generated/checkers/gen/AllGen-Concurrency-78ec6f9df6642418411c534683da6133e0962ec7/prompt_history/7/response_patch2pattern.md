## Bug Pattern

Updating and resetting a per-CPU field with plain, non-atomic reads/writes while it is also accessed from another CPU. Concretely:
- A per-CPU counter (e.g., statc->stats_updates) is modified via plain read-modify-write (+=) and reset via plain store (= 0).
- Another CPU concurrently reads/resets the same field during a flush path.
- Because the per-CPU variable is remotely accessed, using plain loads/stores causes a data race (and possible torn/lost updates).

Pattern indicator:
- Per-CPU variable accessed on CPU X via RMW without locks/atomics:
  statc->stats_updates += delta;
- Concurrent remote access on CPU Y:
  statc->stats_updates = 0;

Fix involves using READ_ONCE/WRITE_ONCE (or atomics) for all cross-CPU accesses to the per-CPU field.
