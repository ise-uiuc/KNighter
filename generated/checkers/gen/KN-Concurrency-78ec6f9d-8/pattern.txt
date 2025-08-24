## Bug Pattern

Unsynchronized cross-CPU access to a per-CPU counter: a per-CPU field is modified with plain read/modify/write (e.g., x += delta; x = 0) on one CPU while another CPU concurrently reads/clears the same field (via per_cpu_ptr(..., cpu)) without using READ_ONCE/WRITE_ONCE or other synchronization. This violates the “local-only” per-CPU assumption, causing data races and possible torn/lost updates.
