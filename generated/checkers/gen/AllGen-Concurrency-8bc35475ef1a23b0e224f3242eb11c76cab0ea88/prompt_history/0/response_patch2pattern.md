## Bug Pattern

Unconditionally reading a shared/concurrently modified field before checking the precondition that guarantees safe access, even when the value is only needed in one guarded branch. This speculative/early read happens without synchronization and can race with concurrent writers, triggering KCSAN/data-race reports despite the value being discarded when the guard is false.

Pattern example:
- Buggy:
  - data = *shared_field;
  - if (safe_to_access) use data;
- Correct:
  - if (safe_to_access) {
      data = *shared_field;
      use data;
    }

In the patch: reading work->data occurred before verifying from_cancel (the condition that implies exclusive ownership), causing a spurious data race. Moving the read inside the from_cancel branch fixes it.
