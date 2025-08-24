## Bug Pattern

Unprotected read/modify/write of a per-CPU field that is accessed from multiple CPUs:
- One path does non-atomic increments on this_cpu_ptr(per-cpu) data (e.g., statc->stats_updates += ...).
- Another path remotely reads/clears the same per-cpu field via per_cpu_ptr(..., cpu) (e.g., statc->stats_updates = 0).
- Because the per-cpu variable is accessed cross-CPU without locks or atomic/READ_ONCE/WRITE_ONCE annotations, concurrent accesses can race and cause torn or lost updates.

In short: plain loads/stores and RMW on a per-CPU counter that is also accessed from other CPUs (remote per-cpu access) -> data race.
