Plan

1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedFieldMap, const MemRegion *, bool)
  - Key: the FieldRegion (or plain pointer region) that represents a resource pointer (e.g., device->bdev_file).
  - Value: true means “this region’s resource was released and must be set to NULL”; when it becomes NULL, erase the entry from the map.
- No separate alias map is needed; we only check direct writes to the exact field/variable.

2. Helper/summarization utilities
- isFputCall(const CallEvent &Call): return true if callee name == "fput".
- KnownFieldRelease table for object-close helpers that release specific fields of the first parameter:
  - struct FieldReleaseEntry { const char *Func; unsigned BaseParamIndex; const char *FieldName; };
  - Initialize with: { "btrfs_close_bdev", 0, "bdev_file" }.
- isKnownFieldReleaseCall(const CallEvent &Call, FieldReleaseEntry &Out): match against the above table.
- markFieldReleased(CheckerContext &C, const Expr *BaseArg, StringRef FieldName):
  - Get base MemRegion from BaseArg via getMemRegionFromExpr(BaseArg, C); ensure it’s a region of a record pointer/object.
  - Find the FieldDecl named FieldName in the pointee record of BaseArg (RecordDecl lookup by name).
  - Compute FieldRegion for that field on that base:
    - SVal FRVal = State->getLValue(FieldDecl*, loc::MemRegionVal(BaseRegion));
    - const MemRegion *FR = FRVal.getAsRegion();
  - Insert (FR -> true) into ReleasedFieldMap.
- markExprReleased(CheckerContext &C, const Expr *PtrExpr):
  - Get MemRegion* R = getMemRegionFromExpr(PtrExpr, C).
  - If R is non-null, insert (R -> true) into ReleasedFieldMap.
- isNullSVal(ProgramStateRef State, SVal V):
  - If V.isZeroConstant(), or if Optional<Loc> L = V.getAs<Loc>() and State->isNull(*L) is true.

3. checkPostCall
- Goal: detect when a resource pointer (struct file*) was released and record it as “must be set to NULL”.
- Steps:
  - If isFputCall(Call):
    - Arg0 = Call.getArgExpr(0); call markExprReleased(C, Arg0).
    - Return true (handled).
  - Else if isKnownFieldReleaseCall(Call, Entry):
    - BaseArg = Call.getArgExpr(Entry.BaseParamIndex).
    - Call markFieldReleased(C, BaseArg, Entry.FieldName).
- Notes:
  - This covers both direct fput(device->bdev_file) and wrapped forms like btrfs_close_bdev(device) known to release device->bdev_file.

4. checkBind
- Goal: mark released fields as “fixed” when explicitly set to NULL.
- Steps:
  - Extract the bound location region: if Optional<loc::MemRegionVal> LV = Loc.getAs<loc::MemRegionVal>(), const MemRegion *Dst = LV->getRegion().
  - If Dst exists in ReleasedFieldMap:
    - If Val is NULL (use isNullSVal(State, Val)): remove Dst from ReleasedFieldMap (problem addressed).
    - Else leave it as true (still stale non-NULL after release).
- Notes:
  - This will catch assignments like device->bdev_file = NULL; or p = NULL; if p itself was released.

5. checkPreCall (optional immediate double-put)
- Goal: catch immediate second release before NULLing, when visible in the same function.
- Steps:
  - If isFputCall(Call):
    - Arg0 region R = getMemRegionFromExpr(Arg0, C).
    - If R is in ReleasedFieldMap and still true, report “Double put/use-after-free of released pointer” (generateNonFatalErrorNode and PathSensitiveBugReport), and return.

6. checkEndFunction
- Goal: at the end of the function, require that any released resource pointer owned/handled by this function is set to NULL.
- Steps:
  - Iterate all entries in ReleasedFieldMap; for each (Region, NeedsNull=true):
    - Heuristics to restrict to this function’s responsibility:
      - Only warn if Region’s super-region belongs to the current stack frame (i.e., a field of a parameter/local of the current function). In practice:
        - For a FieldRegion FR, let BaseR = FR->getSuperRegion(); check BaseR’s stack frame matches Ctx.getLocationContext()->getStackFrame();
      - This matches the pattern like device->bdev_file released inside btrfs_close_one_device but not nulled there.
    - If it matches, emit a bug report:
      - Message: “Released struct file* not set to NULL; may be double-put later.”
  - Cleanup: remove any entries whose regions belong to the current frame to avoid leaking state across calls.

7. checkBranchCondition (optional, conservative)
- If the branch condition references a region in ReleasedFieldMap and it’s still true (not nullified), you may optionally warn with a more targeted message:
  - “Using pointer after release; set it to NULL after fput().”
- This is optional; only enable if you want to flag suspicious non-NULL checks on released pointers.

8. Matching details and constraints
- fput is the primary release API for struct file*; by modeling it, we naturally confine to struct file* resources and avoid false positives.
- For wrapper functions:
  - Maintain a small, explicit summary table mapping function -> released field(s). Start with:
    - { "btrfs_close_bdev", 0, "bdev_file" }
  - The table is easy to extend for other subsystems.
- Type checks (optional):
  - When resolving FieldDecl via FieldName, ensure the field’s type is a pointer type. This helps reduce accidental mis-matches.
- No alias tracking:
  - The checker only requires direct writes to the exact field or pointer to nullify it. This is sufficient for common kernel cleanup patterns and keeps the checker simple.

9. Reporting
- Use std::make_unique<PathSensitiveBugReport> with a concise message.
- For locations, attach the call site of the release (from checkPostCall) as the main diagnostic location and, if available, the expected nulling site (missing) by pointing at function end.

Summary of callbacks used
- checkPostCall: record resource release (fput(...) or summarized wrapper).
- checkBind: detect nulling assignments and clear the obligation.
- checkPreCall (optional): catch immediate double-put on already released region.
- checkEndFunction: enforce “must be set to NULL” before leaving the cleanup function and report if not satisfied.

This plan directly detects the stale pointer after release in btrfs_close_one_device: btrfs_close_bdev(device) releases device->bdev_file via summary; absence of device->bdev_file = NULL triggers a warning at function end.
