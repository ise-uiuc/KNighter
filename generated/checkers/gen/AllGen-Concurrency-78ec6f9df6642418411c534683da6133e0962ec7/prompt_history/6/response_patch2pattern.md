## Bug Pattern

Plain (non-atomic) reads/writes and read-modify-write operations on a per-CPU field that is also accessed by other CPUs (remote per-CPU access), i.e., treating a per-CPU variable as CPU-local when a flush path on another CPU can read/reset it. This causes a cross-CPU data race on a 4-byte field:

- Using “x += …” and “x = 0” on a per-CPU field
- While another CPU concurrently reads/writes the same field

Fix: wrap all concurrent accesses in READ_ONCE()/WRITE_ONCE() (and avoid using the variable after a plain read) to prevent torn/partial reads/writes and KCSAN reports.
