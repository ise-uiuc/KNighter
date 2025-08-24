1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedPtrMap, const MemRegion *, SourceLocation)
  - Tracks pointer lvalue locations (typically struct fields) that have been released but not cleared to NULL. The SourceLocation is where the release happened for better diagnostics.

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks simple pointer aliasing (B aliases A). If one alias is cleared or reinitialized, remove both from ReleasedPtrMap.


2) Helpers and known summaries

- Known “release” functions (direct pointer releases)
  - Maintain a small, explicit table of function names whose arguments release a pointer: fput (param 0), kfree (param 0), kvfree (param 0), vfree (param 0), blkdev_put (param 0), filp_close (param 0), put_device (param 0), sock_release (param 0), bio_put (param 0), kobject_put (param 0).
  - Implement a helper isKnownReleaseFunction(const CallEvent &Call, SmallVectorImpl<unsigned> &ReleaseParams).
    - This is different from functionKnownToDeref: we only add those that definitely release/put/free their pointer argument.

- Owner-based “wrapper” releases (callee frees a specific field of an owner struct)
  - Create a minimal summary for target pattern:
    - Function btrfs_close_bdev (param 0) releases owner->bdev_file.
  - Implement a helper getOwnerReleasedFields(const CallEvent &Call, SmallVectorImpl<std::pair<unsigned, StringRef>> &OwnerParamFieldNames).
    - For “btrfs_close_bdev”, push_back {0, "bdev_file"}.
  - Given an owner argument region and a field name, compute the field region:
    - From the owner argument Expr, get its MemRegion (getMemRegionFromExpr).
    - From the owner’s QualType (Call.getArgExpr(OwnerIdx)->getType()), obtain the RecordDecl and find a FieldDecl whose name matches the field string.
    - Get the field’s lvalue MemRegion using the state’s getLValue(FieldDecl, loc::MemRegionVal(OwnerRegion)).
  - Only track fields (FieldRegion). This keeps the checker specific and reduces noise.

- Common utilities
  - getMemRegionFromExpr(E, C): to get the lvalue region of arguments or fields.
  - functionKnownToDeref(Call, DerefParams): to upgrade a use-site to “definitely dereferences” when reporting use-after-release.
  - ExprHasName(E, "name", C): can be used as a fallback when resolving field names for owner-based summaries if type info is incomplete.


3) Callback selection and implementation details

- checkPostCall (mark “released but not nullified”)
  - Direct release:
    - If isKnownReleaseFunction(Call, ReleaseParams) is true:
      - For each index in ReleaseParams:
        - Let E = Call.getArgExpr(idx).
        - If E is a MemberExpr (struct field) or a DeclRefExpr to a global/static field container, get its MemRegion via getMemRegionFromExpr(E, C).
        - Only proceed if the region is a field-like region (prefer MemberExpr); ignore plain local pointer variables to avoid noise.
        - Insert into ReleasedPtrMap(Region) = E->getExprLoc().
  - Owner-based release (wrapper):
    - If getOwnerReleasedFields(Call, OwnerFieldPairs) yields entries (e.g., btrfs_close_bdev):
      - For each (OwnerIdx, FieldName):
        - Resolve owner argument region (getMemRegionFromExpr(Call.getArgExpr(OwnerIdx), C)).
        - Find FieldDecl by name and then its field MemRegion (as described above).
        - Insert ReleasedPtrMap(FieldRegion) = Call.getSourceRange().getBegin().
  - Also, if the call returns a new pointer and we immediately bind it to a tracked field (rare here), the clean-up will happen in checkBind; no action needed in checkPostCall.

- checkBind (clear state on NULLing or reinitialization; track aliases)
  - If Loc corresponds to a pointer lvalue region (get the MemRegion from Loc if available), and Val is:
    - Explicit NULL:
      - If the region is present in ReleasedPtrMap, remove it.
      - Also remove entries for all aliases of this region (look up in PtrAliasMap both directions).
    - A non-NULL pointer (symbolic or concrete):
      - Treat as reinitialization: remove it from ReleasedPtrMap and also clear its aliases.
  - Track pointer aliases:
    - If S represents an assignment LHS = RHS where both LHS and RHS are pointer lvalues:
      - Get MemRegion for both sides with getMemRegionFromExpr on the corresponding sub-exprs (use the Stmt S to disambiguate).
      - Record alias PtrAliasMap[LHS] = RHS. Do not propagate ReleasedPtrMap here; we only use alias map to mirror clears/reinits.

- checkBranchCondition (flag using released pointer as a validity flag)
  - Pre-visit the condition:
    - Extract any MemberExpr/DeclRefExpr within Condition that denotes a pointer lvalue region:
      - Use a small visitor or findSpecificTypeInChildren to find MemberExpr/DeclRefExpr nodes.
      - For each such expr, get its MemRegion with getMemRegionFromExpr.
      - If any region is in ReleasedPtrMap, emit a warning:
        - Message: “Released pointer used as validity flag; set it to NULL after release.”
      - This catches patterns like if (device->bdev_file), if (ptr != NULL), if (!ptr), etc. No need to evaluate; just the reference is enough.
  - Create the report at the condition’s SourceLocation.

- checkPreCall (flag actual use or double release)
  - For each argument of the call:
    - Get its region via getMemRegionFromExpr.
    - If the region is in ReleasedPtrMap:
      - If the callee is a known release function taking that argument index:
        - Report “Double release: pointer already released and not nullified.”
      - Else if functionKnownToDeref(Call, DerefParams) returns true and includes this argument index:
        - Report “Use-after-release: function dereferences a previously released pointer.”
      - Else:
        - As a fallback, still report “Use of a previously released pointer.” (lower confidence).
  - Point the report to Call.getSourceRange().getBegin() and reference the release location stored in ReleasedPtrMap for extra context.

- checkEndFunction (enforce “null after release” rule)
  - For any region remaining in ReleasedPtrMap at function end:
    - Report: “Pointer released but not set to NULL before function returns.”
    - This is the minimal, robust rule that matches the btrfs fix: after calling the closer, ensure device->bdev_file = NULL within the same function.
  - Use the stored SourceLocation for a note (“released here”).

- No need for checkLocation or evalAssume for this pattern. No need for checkASTDecl/CodeBody.


4) Reporting

- Create a BugType, e.g., “Released-pointer-not-nullified” (category: Memory error).
- Use generateNonFatalErrorNode() and PathSensitiveBugReport with short messages:
  - On branch condition: “Released pointer used as validity flag; set it to NULL after release.”
  - On pre-call deref/double-release: “Use-after-release of pointer” or “Double release of pointer.”
  - On end of function: “Pointer released but not set to NULL before function returns.”
- Add notes:
  - Where it was released (SourceLocation from ReleasedPtrMap).
  - Optionally, where it is used (Condition or Call site).

5) Heuristics to reduce false positives

- Only track MemberExpr (struct/union fields) and optionally globals; skip local auto pointer variables.
- Clear state on any store to the field (NULL or non-NULL).
- Use owner-based summaries only when confident (currently only btrfs_close_bdev -> bdev_file), implemented via field-name match; use ExprHasName as a fallback if the FieldDecl resolution is not straightforward.
- When multiple aliases exist, clearing any alias clears the tracked state for all.


6) How this catches the target bug

- In btrfs_close_one_device:
  - The call to btrfs_close_bdev(device) matches the owner-based summary, so ReleasedPtrMap marks device->bdev_file as released.
  - Before returning, if there is no assignment device->bdev_file = NULL, checkEndFunction reports “Pointer released but not set to NULL before function returns.”
- Alternatively, if later code checks if (device->bdev_file) or calls fput(device->bdev_file), checkBranchCondition/checkPreCall will report use-after-release/double release.
