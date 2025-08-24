Plan

1. Program state
- REGISTER_SET_WITH_PROGRAMSTATE(ReleasedFieldSet, const MemRegion*)
  - Tracks struct fields (and other locations) that were released/closed but not yet overwritten/cleared in the current function.
- (Optional but helpful for better diagnostics) REGISTER_MAP_WITH_PROGRAMSTATE(ReleaseSiteMap, const MemRegion*, const Stmt*)
  - Records the Stmt where the release happened to reference in bug reports.

2. Helper/tables
- Known direct release functions (arg 0 is the released pointer):
  - { "fput", "filp_close", "blkdev_put" }
- Known owner-release functions (releases a specific field of the object passed as parameter):
  - struct OwnerReleaseSpec { const char *FuncName; unsigned ObjParamIndex; const char *FieldName; };
  - Table: { { "btrfs_close_bdev", 0, "bdev_file" } }
- Utilities used:
  - getMemRegionFromExpr(E, C): to obtain MemRegion* from expressions/args.
  - findSpecificTypeInChildren<T>(S), findSpecificTypeInParents<T>(S, C): to find MemberExpr inside branch conditions if needed.
  - ExprHasName(E, "bdev_file", C): only as a last resort to help field-name matching when necessary.
- Build a FieldRegion from an object region + field name:
  - From the object argument expression, get its MemRegion (should be a TypedValueRegion pointing to a Record).
  - Retrieve pointee record type (RecordDecl) from the argument’s QualType.
  - Lookup the FieldDecl by name (e.g., "bdev_file").
  - Use MemoryRegionManager::getFieldRegion(FieldDecl*, BaseRegion) to obtain the specific field region for that object.
  - Add that field region to ReleasedFieldSet.

3. checkPostCall (identify releases and mark the field as released)
- Direct release:
  - If callee name is in Known direct release functions, get arg0 region via getMemRegionFromExpr.
  - If the argument is a struct field (MemberExpr) or any region representing a released pointer, insert its region into ReleasedFieldSet and record call site in ReleaseSiteMap.
- Owner release:
  - If callee name matches an entry in OwnerReleaseSpec:
    - Obtain the object-parameter expression by index and its MemRegion (base).
    - Compute the FieldRegion for the named field (e.g., "bdev_file") as described above.
    - Insert FieldRegion into ReleasedFieldSet and record call site.
- Do nothing if the argument/field’s region is unknown.

4. checkBind (discharge the obligation when the field is overwritten)
- Triggered on every store/bind.
- Extract the destination region (Loc.getAsRegion()); if this region is present in ReleasedFieldSet:
  - If Val is a concrete zero (NULL), remove the region from ReleasedFieldSet and ReleaseSiteMap (cleared).
  - If Val is a non-unknown value (e.g., reassigned a new pointer), also remove it (reinitialized).
  - If Val is Unknown, leave the state unchanged.
- This handles assignments like device->bdev_file = NULL and also reinitializations.

5. checkBranchCondition (catch “if (field)” use after release)
- Inspect the condition to find a MemberExpr inside it (use findSpecificTypeInChildren<MemberExpr>(Condition)).
- If found, get its MemRegion (getMemRegionFromExpr on the MemberExpr).
- If that region is in ReleasedFieldSet, emit a bug:
  - Message: “released struct field used as validity check”
  - Use generateNonFatalErrorNode and PathSensitiveBugReport.
  - Optionally add a note pointing to the release site via ReleaseSiteMap.

6. checkPreCall (catch re-use or double-close on a released field)
- For each argument of the call:
  - Get its region; if it is in ReleasedFieldSet:
    - Emit a bug: “use-after-free/double close on released field”
    - This catches patterns like fput(device->bdev_file) again or passing released field to functions that use it.
- Optionally use functionKnownToDeref(Call, DerefParams) to increase precision:
  - If the callee is known to dereference pointer parameters and the corresponding argument region is in ReleasedFieldSet, report the same bug.

7. checkEndFunction (report missing NULLing before returning)
- At function end, iterate over ReleasedFieldSet:
  - For each remaining region, emit a bug:
    - Message: “released struct field not cleared before return”
    - Add a note to the recorded release site if available.
- This specifically flags the btrfs_close_one_device pattern where device->bdev_file is released in a callee (btrfs_close_bdev) but not set to NULL in the same function.

8. Reporting details
- Always create a non-fatal error node to keep analysis going.
- Keep messages short:
  - “released struct field used as validity check”
  - “use-after-free/double close on released field”
  - “released struct field not cleared before return”
- Optionally include the field name in the message if it can be reliably obtained (e.g., “bdev_file”).

9. Notes on scope and heuristics
- The checker is intra-procedural and path-sensitive within a function:
  - It will precisely catch:
    - Direct releases like fput(device->field) without a subsequent field clear/reinit.
    - Indirect owner releases via known functions (e.g., btrfs_close_bdev) that invalidate known field(s) of the passed object.
    - Subsequent uses in branch conditions and parameter passing within the same function.
- To keep it simple, alias tracking is not implemented. We only track the field region itself. This matches the target pattern where code typically checks the same field later via MemberExpr.
- Extend OwnerReleaseSpec if needed for other subsystems with similar patterns.
