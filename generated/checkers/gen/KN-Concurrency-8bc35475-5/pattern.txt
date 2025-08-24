## Bug Pattern

Speculative/unconditional read of a shared, concurrently modified field before checking the guard that guarantees safe access. In __flush_work(), work->data was read unconditionally:

  data = *work_data_bits(work);
  if (from_cancel && ...) { ... }

Even though the value is only relevant when from_cancel is true, performing the read outside that guard accesses a racy field without established ownership, triggering KCSAN data-race reports. The correct pattern is to first check the condition that ensures exclusive access (from_cancel) and only then read the shared field.
