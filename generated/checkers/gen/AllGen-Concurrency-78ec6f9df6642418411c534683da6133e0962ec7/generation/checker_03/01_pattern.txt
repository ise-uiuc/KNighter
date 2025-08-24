## Bug Pattern

Unsynchronized read-modify-write of a per-CPU field that is also accessed “remotely” from other CPUs.

Specifically, a per-CPU counter (statc->stats_updates) is:
- incremented on the local CPU with plain loads/stores (“+=”),
- concurrently read and zeroed by another CPU via per_cpu_ptr(..., cpu).

Because ordinary loads/stores are used instead of READ_ONCE/WRITE_ONCE (or atomics), this remote access pattern causes data races and potential torn reads/writes on the same 4-byte location.
