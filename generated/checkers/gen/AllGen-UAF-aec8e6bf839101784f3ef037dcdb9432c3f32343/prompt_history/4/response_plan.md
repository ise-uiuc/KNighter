Plan

1. Program State

- REGISTER_SET_WITH_PROGRAMSTATE(ReleasedFields, const FieldRegion *)
  - Tracks struct fields that have been released/closed but not reset to NULL. We only add fields that we can precisely identify as fields via MemberExpr (or via known “container-release” calls).
- REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedOrigin, const FieldRegion *, const Stmt *)
  - Remembers the Stmt (typically the call) where the release was observed, to anchor diagnostics.

Rationale: We only need to know which field (memory location) is “logically freed” and whether it’s later nullified. No alias map is necessary because we only flag the specific field not being set to NULL.

2. Helper Utilities

- getFieldRegionFromMemberExpr(const MemberExpr *ME, CheckerContext &C)
  - Use getMemRegionFromExpr(ME->getBase(), C) to get the base region, then build the FieldRegion using C.getStoreManager().getFieldRegion(ME->getMemberDecl(), cast<SubRegion>(BaseRegion)).
- findFieldDeclByNameInType(QualType QT, StringRef FieldName)
  - If QT is a RecordType, iterate the fields to find a FieldDecl whose getNameAsString() equals FieldName.
- getFieldRegionForNamedFieldOfBaseExpr(const Expr *Base, StringRef FieldName, CheckerContext &C)
  - Combines the two functions above: from Base expression get its region, then lookup FieldDecl by name on the record type of Base, then build FieldRegion via StoreManager.

Note: These are small internal helpers in the checker; they are straightforward given Clang APIs. The provided getMemRegionFromExpr utility is used to get the base region.

3. Known Release Modeling

- We model only the minimal set needed for this bug pattern to avoid false positives:
  - Direct release of file pointers: fput(ptr)
    - If ptr is a MemberExpr that names a field, we treat that field as released.
  - Container release where a function frees a specific field of its struct-parameter:
    - btrfs_close_bdev(struct btrfs_device *dev) releases dev->bdev_file internally (via fput).
      - We’ll handle this as a special case: add dev->bdev_file to ReleasedFields at the call site.
- Internal helpers:
  - bool isDirectFileRelease(const CallEvent &Call): returns true if callee is "fput".
  - bool isContainerReleaseBtrfsCloseBdev(const CallEvent &Call): returns true if callee is "btrfs_close_bdev".
  - For the latter, the released field name is the literal "bdev_file".

4. Callbacks and Logic

4.1 checkPostCall (record releases)

- If isDirectFileRelease(Call):
  - Obtain the first argument expression E0.
  - If E0->IgnoreParenImpCasts() is a MemberExpr (ME), get FieldRegion FR via getFieldRegionFromMemberExpr(ME, C).
  - Add FR to ReleasedFields; set ReleasedOrigin[FR] = Call.getOriginExpr() (or CallExpr stmt).
- Else if isContainerReleaseBtrfsCloseBdev(Call):
  - Let Base = first argument expression (dev).
  - Build FieldRegion FR for field name "bdev_file" using getFieldRegionForNamedFieldOfBaseExpr(Base, "bdev_file", C).
  - If FR is valid, add to ReleasedFields and set ReleasedOrigin[FR] = Call.getOriginExpr().

4.2 checkBind (detect nulling and clear state)

- We are interested in assignments to fields: if Loc is a location SVal whose region is a FieldRegion FR and FR is in ReleasedFields:
  - If Val is a null pointer constant:
    - Remove FR from ReleasedFields and erase FR from ReleasedOrigin.
- How to test for null:
  - Check if Val is a loc::ConcreteInt equal to 0, or Val.isZeroConstant() if available, or EvaluateExprToInt/Eval to 0 when the RHS is an expression.
- This captures: device->bdev_file = NULL; and clears the “released but not nulled” status.

4.3 checkPreCall (catch immediate double-release on the same field)

- If isDirectFileRelease(Call):
  - If arg0 is a MemberExpr ME and its FieldRegion FR is in ReleasedFields, report an immediate double-release/use-after-free on that field.
- If isContainerReleaseBtrfsCloseBdev(Call):
  - Compute FR for "bdev_file" as above. If FR is in ReleasedFields, report immediate double-release.

Report:
- Generate a non-fatal error node and a PathSensitiveBugReport with message: "Double release of field 'bdev_file'".
- Use ReleasedOrigin[FR] for a note: "Field was released here".

4.4 checkEndFunction (finalize: released but not nulled)

- At function end, iterate ReleasedFields in the current state. For each FR still present:
  - Emit a bug: "Released field not set to NULL" (short, clear).
  - If ReleasedOrigin has an entry for FR, add a note pointing at the release site.
- Rationale: If a function releases a struct field (e.g., via btrfs_close_bdev(dev)) and returns without setting the corresponding pointer field to NULL, later code may test it for non-NULL and reuse it, leading to UAF/double-release (exactly the btrfs fix).

5. Paths and Minimizing False Positives

- Scope: Only track fields named "bdev_file" (container release) and fields passed to fput(.) when they are explicit MemberExprs. This bounds the checker to the targeted kernel pattern and avoids broad false positives.
- Path sensitivity: Removing FR on assignments to NULL ensures no report on paths that correctly reset the pointer. Only paths that miss the NULLing will report.
- Aliasing: Not needed; we only require the specific field itself be set to NULL, matching the kernel style and the provided patch.

6. Reporting Details

- Bug 1 (end-of-function): "Field 'bdev_file' released but not set to NULL"
  - Primary location: function end or at the point we decide to report; include a note at release site (ReleasedOrigin[FR]).
- Bug 2 (immediate misuse): "Double release of field 'bdev_file'"
  - Primary location: the second release Call; include a note for the first release (ReleasedOrigin[FR]).

7. Use of Provided Utilities

- getMemRegionFromExpr to get base regions for building FieldRegions.
- findSpecificTypeInChildren can help extract MemberExpr from call arguments when wrapped in casts or macros.
- ExprHasName is not strictly necessary here, but can be used defensively to confirm the field name when dealing with complex expressions.

8. Summary of Steps to Implement

- Define ReleasedFields set and ReleasedOrigin map as program state traits.
- Implement helpers to:
  - Identify release calls (fput, btrfs_close_bdev).
  - Build FieldRegion for a MemberExpr or for a named field ("bdev_file") of a struct argument.
- In checkPostCall:
  - Record releases into ReleasedFields and ReleasedOrigin.
- In checkBind:
  - Clear entries when the field gets assigned NULL.
- In checkPreCall:
  - If a second release is attempted on a tracked field, report double-release.
- In checkEndFunction:
  - If any released field remains not nulled, report "released field not set to NULL".

This directly detects the btrfs pattern: after calling btrfs_close_bdev(device), ensure device->bdev_file is set to NULL before function returns; otherwise report. It also catches immediate double fput on device->bdev_file if it happens in the same function.
