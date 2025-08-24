Plan

1) Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(AllocKindMap, const MemRegion*, unsigned)
  - 0 = Unknown/not tracked
  - 1 = Zeroed allocation (kzalloc/kcalloc)
  - 2 = Possibly-uninitialized allocation (kmalloc/kmalloc_array/kmalloc_node)
- REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitSizeMap, const MemRegion*, uint64_t)
  - Records the last known byte count explicitly initialized via memset/memzero_explicit that starts at the base pointer. If length can’t be evaluated to a constant, do not record.
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer aliases so we can resolve the “from” argument in copy_to_user back to the original allocation.

Helper utilities to implement:
- const MemRegion* canonical(const MemRegion* R):
  - Return R ? R->getBaseRegion() : nullptr.
  - Resolve transitive aliases via PtrAliasMap until a fixed point is reached.
- void setAllocKind(ProgramStateRef, const MemRegion*, unsigned):
  - Store into AllocKindMap for canonical region and erase ZeroInitSizeMap entry.
- Optional: wipe maps entries when region is not a pointer anymore or is null; keep it simple and rely on path-sensitivity.

2) Allocation modeling (checkPostCall)
- Identify allocation functions by callee name:
  - Uninitialized: "kmalloc", "kmalloc_array", "kmalloc_node"
  - Zeroed: "kzalloc", "kcalloc"
- Get the returned region:
  - const MemRegion* RetReg = Call.getReturnValue().getAsRegion(); if null, try getMemRegionFromExpr(Call.getOriginExpr(), C). Apply canonical().
- Update state:
  - For kzalloc/kcalloc: setAllocKind(State, RetReg, 1)
  - For kmalloc/kmalloc_array/kmalloc_node: setAllocKind(State, RetReg, 2)
- We do not need to compute allocation sizes for this checker.

3) Track explicit initialization (checkPostCall)
- Detect calls that initialize memory:
  - "memset" and "memzero_explicit"
- Extract arguments:
  - dest = arg0, value = arg1 (for memset), len = arg2
- Get canonical region of dest with canonical(getMemRegionFromExpr(arg0, C)).
- Evaluate length with EvaluateExprToInt; if it succeeds, store the length (as uint64_t) in ZeroInitSizeMap for that canonical region.
  - For memset: it does not matter whether the value is 0 or not; any fill initializes bytes. If length is known, record it.
  - For memzero_explicit: record the length similarly.
- If length cannot be evaluated to a constant, do not update ZeroInitSizeMap (keep it simple to avoid false positives assumptions).

4) Alias tracking (checkBind)
- When a pointer value is assigned to another pointer (e.g., p2 = p1):
  - Extract MemRegion for LHS and RHS via getMemRegionFromExpr; restrict to pointer-typed regions.
  - Compute canonical regions for both.
  - If canonical RHS is tracked (in AllocKindMap or ZeroInitSizeMap), record PtrAliasMap[LHS_canon] = RHS_canon to propagate provenance.
  - Do not copy the maps; rely on canonical lookup to resolve.
- Also handle simple initializations in DeclStmt (post-visit of DeclStmt can be handled by checkBind path-sensitively; no extra work needed).

5) Reporting at copy_to_user (checkPreCall)
- Match callee "copy_to_user".
- Extract arguments:
  - to = arg0, from = arg1, len = arg2.
- Resolve the “from” region:
  - FromReg = canonical(getMemRegionFromExpr(arg1, C)).
  - If FromReg is null, return.
- Query AllocKindMap[FromReg]:
  - If kind == 1 (Zeroed): safe; return.
  - If kind != 2 (not tracked): return.
  - If kind == 2 (Possibly-uninitialized):
    - Try to EvaluateExprToInt on len; if success set CopyLen.
    - Look up ZeroInitSizeMap[FromReg]:
      - If present and ZeroedBytes >= CopyLen (when CopyLen known) => safe; return.
      - Otherwise, this is a potential info leak. Report.
    - If CopyLen is unknown and ZeroInitSizeMap has no entry for FromReg, report (we did not observe any bulk initialization; keep it simple).

6) Optional robustness (keep simple)
- We do not attempt to track partial writes, field writes, or initialization via struct literals.
- We do not attempt range-based initialization; we only use bulk memset/memzero_explicit and zeroed allocators.
- We only match the plain "copy_to_user" callee name at source; instrumented or inlined variants will still present as "copy_to_user" in typical kernel sources.

7) Bug report
- Create a Checker BugType once: "Kernel info leak".
- On detection in checkPreCall:
  - Generate a non-fatal error node and emit a PathSensitiveBugReport.
  - Message: "copy_to_user may leak uninitialized kernel memory from kmalloc buffer. Use kzalloc or memset to initialize."
  - Add the call expression range of copy_to_user as the primary range.
  - Optionally, if available, note the allocation site by attaching a trackback visitor or storing the last allocation CallExpr region (keep it simple: primary range is sufficient).

8) Summary of callbacks implemented
- checkPostCall:
  - Handle kmalloc/kzalloc/kmalloc_array/kcalloc/kmalloc_node to set allocation kind.
  - Handle memset/memzero_explicit to record last initialized size for the region.
- checkBind:
  - Track pointer aliases p2 = p1 in PtrAliasMap.
- checkPreCall:
  - On copy_to_user, check if the source buffer originates from kmalloc and is not fully initialized (no zeroed alloc and no sufficient memset). If so, report.

This plan detects the target pattern in the patch: kmalloc buffer passed to copy_to_user without whole-buffer initialization, and it naturally stops warning when kzalloc (or a full memset) is used.
