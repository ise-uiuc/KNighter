Plan to detect “released member pointer not cleared to NULL, later used/double-freed”

1) Program state
- REGISTER_SET_WITH_PROGRAMSTATE(ReleasedMembers, const MemRegion*)
  - Tracks member pointer regions (FieldRegion) that have been released/put and not yet cleared to NULL.
- No alias map is required to keep the checker simple and robust.

2) Helper classification functions
- isReleaseLikeFunction(const CallEvent &Call):
  - Identify release/put/free-like APIs by callee name (exact-match table, with a conservative suffix heuristic).
  - Suggested exact names: "fput", "kfree", "kvfree", "filp_close", "blkdev_put", "bio_put", "sock_release", "put_device".
  - Optional heuristic: name contains "free" or ends with "put", but only use if the arg is a pointer to a resource-like type to avoid noise.
- isKnownObjectMemberReleaser(const CallEvent &Call, SmallVectorImpl<StringRef> &ReleasedFields):
  - A small table of functions that release specific member fields of their first parameter (object pointer), e.g.:
    - "btrfs_close_bdev" releases ["bdev_file"] (and possibly "bdev" if desired).
  - This lets us model releases that happen inside callee (the exact pattern from the patch).
- getFieldRegionFromObjectAndName(const Expr *ObjArg, StringRef FieldName, CheckerContext &C):
  - Given an object expression (e.g., device) and a field name (e.g., "bdev_file"), obtain the FieldRegion for Obj->Field.
  - Implementation: retrieve base MemRegion for the object pointer; fetch pointee RecordDecl; find FieldDecl by name; use State->getLValue(FieldDecl, baseRegion) and extract the MemRegion.
- isNullSVal(SVal V):
  - Returns true if V is a null/zero constant.
- getFieldRegionFromExpr(const Expr *E, CheckerContext &C):
  - Use getMemRegionFromExpr(E, C). Only consider regions that dyn_cast to FieldRegion (member pointers).
- Shortcuts to use provided utilities:
  - ExprHasName(Call.getOriginExpr()->getCallee(), "name", C) to match names when appropriate.
  - functionKnownToDeref(Call, DerefParams) to flag UAF when a released pointer is passed to a function that dereferences that param.

3) checkPostCall
- Purpose: Mark member pointers as released.
- Steps:
  - Case A: Direct release/put/free
    - If isReleaseLikeFunction(Call):
      - For each parameter index of interest (typically 0), obtain the argument expression and its region via getFieldRegionFromExpr(argExpr, C).
      - If region is a FieldRegion, add it to ReleasedMembers.
  - Case B: Release happening in the callee on an object parameter (btrfs_close_bdev)
    - If isKnownObjectMemberReleaser(Call, ReleasedFields):
      - Take the first argument as the object expression.
      - For each field name in ReleasedFields, get the field region with getFieldRegionFromObjectAndName(ObjArg, FieldName, C).
      - Add those field regions to ReleasedMembers.
- Notes:
  - Skip non-member regions to keep the checker focused on the target pattern.
  - Do not emit reports here.

4) checkPreCall
- Purpose: Detect double release and UAF through calls that dereference.
- Steps:
  - If isReleaseLikeFunction(Call):
    - Get the member pointer region for the relevant argument as above.
    - If that region exists in ReleasedMembers, report:
      - Message: "Double release of a member pointer; set it to NULL after releasing."
  - If functionKnownToDeref(Call, DerefParams):
    - For each param index in DerefParams, get the region.
    - If any region is in ReleasedMembers, report:
      - Message: "Use-after-free: released member pointer passed to a function that dereferences it."
- Reporting:
  - Use generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>.
  - Keep message short. Do not auto-remove state on report; let normal flow continue.

5) checkLocation
- Purpose: Catch dereference of released pointers in code (e.g., *ptr, ptr->field).
- Steps:
  - If IsLoad or store on a location Loc and the base region of Loc corresponds to a member pointer region found in ReleasedMembers (either the FieldRegion itself or a region derived from it), emit:
    - Message: "Use-after-free: released member pointer dereferenced."
- Implementation detail:
  - Extract the MemRegion from Loc. If it’s a FieldRegion included in ReleasedMembers (or derived from that pointer), warn.

6) checkBranchCondition
- Purpose: Detect “if (member_ptr)” style gates on released pointers that commonly guard a second put/free.
- Steps:
  - Examine Condition:
    - If it contains a MemberExpr representing a pointer field; get its region via getFieldRegionFromExpr(findSpecificTypeInChildren<MemberExpr>(Condition), C).
    - Also handle comparisons against NULL or unary ! pattern.
  - If the region is in ReleasedMembers, issue a warning at the condition:
    - Message: "Dangling member pointer used in condition after release."
  - Optional refinement (if you want fewer false positives):
    - Try to find in the corresponding 'then' branch a call to a release-like function on the same member pointer using a shallow child scan. If found, prefer a more specific message:
      - "Double release: conditionally freeing a released member pointer."
    - Use findSpecificTypeInChildren to find CallExprs and match arguments.

7) checkBind
- Purpose: Clear the “released” mark once the member pointer is set to NULL; also clear if it’s overwritten.
- Steps:
  - If Loc corresponds to a FieldRegion (member) and that region is in ReleasedMembers:
    - If Val is NULL (isNullSVal(Val)), remove the region from ReleasedMembers.
    - Else if Val is a non-null pointer or Unknown, conservatively remove it as well (the code overwrote the stale pointer, so it’s no longer a dangling reference).
- This models “device->bdev_file = NULL;” which is the fix in the patch.

8) checkRegionChanges
- Purpose: Clean up state on invalidation.
- Steps:
  - When regions are invalidated (due to calls/scope exit), remove any matching regions from ReleasedMembers where either the field itself or its base object is part of ExplicitRegions/Regions.

9) Optional: checkEndFunction
- Not required. To keep the checker focused and low-noise, do not emit style warnings like “released member pointer not set to NULL” at function exit.
- The harmful patterns are already caught at the points of use (second free or deref/condition).

10) Notes on matching the target patch precisely
- Ensure isKnownObjectMemberReleaser includes:
  - { Name: "btrfs_close_bdev", ReleasedFields: ["bdev_file"] }
- This allows the checker to mark device->bdev_file as released right after btrfs_close_bdev(device) returns. If later code performs:
  - if (device->bdev_file) fput(device->bdev_file);
  - The checker will flag it either at the condition (checkBranchCondition) or at fput’s pre-call (checkPreCall) as a double release / UAF.
- The correct pattern (as in the patch) “device->bdev_file = NULL;” is recognized by checkBind and clears the released state, preventing false positives.

11) Bug report messages
- Double release: "Double release of a member pointer; set it to NULL after releasing."
- Use-after-free on call: "Use-after-free: released member pointer passed to a function that dereferences it."
- Use-after-free on deref: "Use-after-free: released member pointer dereferenced."
- Condition on released pointer: "Dangling member pointer used in condition after release."

12) Summary of used callbacks
- checkPostCall: mark released member pointers (direct release calls and known object-member releasers).
- checkPreCall: report double release and UAF via functions known to dereference.
- checkLocation: report dereferences on released pointers.
- checkBranchCondition: report boolean checks on released pointers (commonly guard second frees).
- checkBind: clear the released mark when pointer fields are set to NULL or overwritten.
- checkRegionChanges: cleanup state on region invalidation.
