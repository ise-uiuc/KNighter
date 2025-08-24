## Bug Pattern

Plain (non-atomic) read-modify-write and stores on a per-CPU field that is also accessed from other CPUs (remote per-CPU access during flush), i.e., assuming per-CPU isolation where it does not hold. Specifically:
- Updating and resetting a per-CPU counter (statc->stats_updates) with ordinary loads/stores (x += inc; x = 0) while another CPU may concurrently read/reset the same 4-byte location.
- No READ_ONCE/WRITE_ONCE (or locking/atomics) around these accesses, causing data races and possible torn/partial reads/writes.

The fix annotates all accesses with READ_ONCE/WRITE_ONCE and bases atomic updates on a locally captured value to avoid races.
