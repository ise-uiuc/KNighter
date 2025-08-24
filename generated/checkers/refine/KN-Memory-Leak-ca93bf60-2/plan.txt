Plan

1. Program State
- REGISTER_MAP_WITH_PROGRAMSTATE(TempBufMap, const MemRegion*, const Stmt*)
  - Key: the pointee MemRegion of a temporary heap buffer that must be kfree’d.
  - Value: the allocation site (the CallExpr Stmt) to improve diagnostics.
- Rationale: We only need to know “this buffer must be freed later.” No alias map is required because free()-like calls receive the same pointee region we track.

2. Helper Utilities
- isTempAllocReturningKmem(const CallEvent &Call)
  - Return true when callee is a known function that returns a kmalloc’d buffer which must be freed with kfree. For this checker, keep it minimal: recognize "nvmem_cell_read".
- isFreeLike(const CallEvent &Call)
  - Return true if callee is "kfree" or "kvfree".
- const MemRegion* getReturnedRegion(const CallEvent &Call, CheckerContext &C)
  - Return Call.getReturnValue().getAsRegion().
- const MemRegion* getFreedRegion(const CallEvent &Call, CheckerContext &C)
  - Return getMemRegionFromExpr(Call.getArgExpr(0), C).
- reportLeak(const MemRegion *R, const Stmt *AllocSite, const Stmt *Sink, CheckerContext &C)
  - Emit report at Sink (the ReturnStmt), with a note pointing to AllocSite.

3. Callbacks and Logic
- checkPostCall(const CallEvent &Call, CheckerContext &C) const
  - Track temporary allocations
    - If isTempAllocReturningKmem(Call) is true:
      - Get returned region: R = getReturnedRegion(Call, C).
      - If R is non-null:
        - State = State->set<TempBufMap>(R, Call.getOriginExpr()).
        - C.addTransition(State).
  - (Do not handle free here; we will do it in pre-call to ensure our bookkeeping happens before the region is invalidated by the model of kfree.)

- checkPreCall(const CallEvent &Call, CheckerContext &C) const
  - Handle freeing (clear from map when freed)
    - If isFreeLike(Call) is true:
      - FR = getFreedRegion(Call, C).
      - If FR is non-null and FR is in TempBufMap:
        - State = State->remove<TempBufMap>(FR).
        - C.addTransition(State).

- checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const
  - Detect returning with outstanding temporary buffers (leak on early return)
    - State = C.getState().
    - Fetch TempBufMap. If empty, return.
    - Optional suppression: if the function returns a pointer and that pointer’s region equals a tracked region, skip (transfer of ownership).
      - Get RetExpr = RS->getRetValue(). If RetExpr exists and its SVal has a region RetR:
        - If RetR is a key in TempBufMap, return (do not flag).
    - Otherwise, report leak:
      - Pick one entry (R, AllocSite) from TempBufMap (e.g., the first).
      - reportLeak(R, AllocSite, RS, C).
    - Rationale: In the target pattern, the ReturnStmt is reached on devm_krealloc failure before the temp buffer (efuse) is kfree’d; this path will have that temporary still present in TempBufMap, so the ReturnStmt triggers the report.

4. What This Checker Specifically Catches
- Temporary buffer allocated by nvmem_cell_read() (e.g., u8 *efuse = nvmem_cell_read(...);).
- The buffer is intended to be kfree’d later in the success path.
- A subsequent early return (e.g., after devm_krealloc failure) occurs before kfree(efuse), causing a leak.
- The checker flags any ReturnStmt encountered while a tracked (unfreed) temporary buffer is still outstanding.

5. Why No Alias Map Is Needed
- We track the pointee MemRegion of the allocated buffer. free()-like calls take the same pointee region regardless of which local variable holds it (p, q, alias, etc.). getMemRegionFromExpr on the free argument yields the pointee MemRegion, which matches our tracked key.

6. Bug Report
- Title: “Temporary buffer allocated by nvmem_cell_read() is not freed on early return”
- Message: “Leaked temporary buffer; call kfree() before returning.”
- Attach a note at the allocation site (AllocSite).
- Use std::make_unique<PathSensitiveBugReport>. Create the bug type once and reuse. Generate a non-fatal error node.

7. Scope and Noise Control
- Keep the allocator list minimal (only “nvmem_cell_read”) to avoid false positives.
- Only report on ReturnStmt (not at function end) to align with the intended early-return pattern.
- Skip reporting when the function returns the tracked pointer (possible ownership transfer).

8. Summary of Steps
- State:
  - REGISTER_MAP_WITH_PROGRAMSTATE(TempBufMap, const MemRegion*, const Stmt*)
- checkPostCall:
  - If callee == nvmem_cell_read, add returned region to TempBufMap with the CallExpr as AllocSite.
- checkPreCall:
  - If callee == kfree or kvfree, remove the pointee region (argument) from TempBufMap.
- checkPreStmt(ReturnStmt):
  - If TempBufMap non-empty and not returning one of the tracked pointers, report leak at this return, noting the allocation site.

This minimal, path-sensitive plan precisely flags the target pattern: allocating a temporary buffer (nvmem_cell_read), then returning early (e.g., due to devm_krealloc failure) without kfree’ing the temporary buffer.
