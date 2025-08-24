## Bug Pattern

Non-atomic access to a per-CPU counter that is also accessed remotely:
- A per-CPU field (e.g., statc->stats_updates) is updated with plain "+=" and "=" on one CPU while another CPU concurrently reads/writes the same field via per_cpu_ptr(..., cpu) during a flush.
- This cross-CPU, lockless read-modify-write and reset using plain loads/stores (without READ_ONCE/WRITE_ONCE or atomics) causes a data race and potential torn/partial reads/writes.
