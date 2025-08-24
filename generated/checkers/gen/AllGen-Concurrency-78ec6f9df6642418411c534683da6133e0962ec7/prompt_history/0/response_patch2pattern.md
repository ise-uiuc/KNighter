## Bug Pattern

Non-atomic read/modify/write of a per-CPU field that is also accessed from other CPUs (remote percpu access), leading to a data race.

Example pattern:
- Hot path:
  statc->stats_updates += abs(val);   // plain RMW (implicit read + write)
- Remote flush path (different CPU):
  statc->stats_updates = 0;           // plain write

Because the same 4-byte field is updated and cleared from different CPUs without locking or atomic/once annotations, accesses can be torn or reordered. The fix is to wrap accesses with READ_ONCE()/WRITE_ONCE() (and avoid non-atomic RMW) to prevent races/partial reads.
