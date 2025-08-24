Plan to detect “released member pointer not set to NULL” (leading to later double-free/UAF)

1) Program state customizations
- REGISTER_SET_WITH_PROGRAMSTATE(ReleasedSet, const MemRegion*)
  - Tracks pointer regions that have been released/closed and have not been nullified yet.
- REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedOriginMap, const MemRegion*, const Stmt*)
  - Remembers the statement (typically the call) that performed the release, for precise diagnostics at report time.

2) Known release tables
- Release-by-pointer functions (directly release their pointer argument). Maintain a small static table of names and 0-based parameter indices:
  - Examples: fput (0), blkdev_put (0), kfree (0), kvfree (0), put_device (0), filp_close (0) as needed.
- Release-by-container functions (release specific member fields of a struct pointer parameter). Maintain a table of:
  - Function name, parameter index that is the “container” (struct pointer), and a list of member names that are released by the callee.
  - Include for this bug: btrfs_close_bdev: param 0; members ["bdev", "bdev_file"].
  - This is intentionally a small, explicit list to keep the checker simple and effective.

3) checkPostCall — mark regions as released
- Get callee identifier from Call.getCalleeIdentifier(). If none, return.
- For release-by-pointer functions:
  - For each listed parameter index, retrieve the corresponding argument expression and its MemRegion via getMemRegionFromExpr().
  - If region is non-null, add it to ReleasedSet and record ReleasedOriginMap[region] = Call.getOriginExpr() or Call.getSourceRange start stmt.
- For release-by-container functions:
  - Get the MemRegion for the container argument.
  - If it’s a record region (or a pointer to one), obtain the base (e.g., CXXRecordDecl/RecordDecl) and look up FieldDecls by name (exact string match).
  - For each member name in the table:
    - Build the FieldRegion for that member under the container’s base region (RegionManager::getFieldRegion(FieldDecl*, baseRegion)).
    - Add each FieldRegion to ReleasedSet and record the Call as the origin in ReleasedOriginMap.
- Rationale: This models the effect of both direct releases (fput(ptr)) and callee-releases of struct members (btrfs_close_bdev(device) releases device->bdev_file).

4) checkBind — clear released state on (re)assignment
- If Loc.getAsRegion() yields a region R and R is in ReleasedSet:
  - Remove R from ReleasedSet and ReleasedOriginMap unconditionally on any assignment.
  - Special-case not required: if assigned NULL, it is the desired fix; if assigned a new non-NULL value, the pointer is no longer stale and shouldn’t trigger a “not set to NULL” warning later.
- Additionally handle common syntactic forms:
  - Member assignments (e.g., device->bdev_file = NULL;).
  - Variable assignments (DeclRefExpr).
- This keeps false positives low and recognizes “reset to NULL” or “re-initialize” as fixing the state.

5) checkPreCall — detect double release on stale pointers
- If the callee is a release-by-pointer function:
  - Get the argument region for the known release parameters.
  - If the region is present in ReleasedSet, report a bug:
    - Message: "Double release of stale pointer."
    - Create a non-fatal error node with generateNonFatalErrorNode().
    - Use PathSensitiveBugReport, attach a note pointing to the origin Stmt from ReleasedOriginMap[region] like "Pointer was released here."
- This precisely fires on the problematic “if (ptr) release(ptr)” after having released earlier without resetting the pointer to NULL.

6) checkEndFunction — detect “released but not nullified” at function exit
- At end of the function (checkEndFunction), iterate over ReleasedSet:
  - Only consider FieldRegion entries (member pointers). Ignore plain locals/DeclRegions to focus on the intended pattern (struct member left non-NULL).
  - For each such region R, retrieve origin from ReleasedOriginMap[R] and emit a warning that the released member pointer was not set to NULL before function return:
    - Message: "Released member pointer not set to NULL."
    - The bug location can be at the function end, and add a note at the origin release call.
- This captures the exact scenario in the provided patch: btrfs_close_bdev(device) releases members, but the caller function forgets to nullify all released member pointers.

7) Optional: checkBranchCondition (not required for minimal checker)
- Not strictly necessary because double-release detection in checkPreCall already fires when a stale pointer is used in a guarded “if (ptr)” and re-released.
- If desired, you can inspect conditions like “if (dev->field)” or comparisons to NULL and, if the field is in ReleasedSet, add a path note or a weaker warning. Prefer to keep it off to avoid noise.

8) Bug report details
- Use concise messages per Suggestions:
  - Double-release report: "Double release of stale pointer."
  - Exit report: "Released member pointer not set to NULL."
- Use std::make_unique<PathSensitiveBugReport>.
- Provide a path note showing where the original release occurred via ReleasedOriginMap.

9) Implementation notes/heuristics
- Use getMemRegionFromExpr to resolve expression to MemRegion; for MemberExpr this should yield a FieldRegion, which is ideal for our tracking.
- When handling container closers:
  - Resolve param region; if it’s a pointer to record, get the pointee record decl to find FieldDecls.
  - Use exact field name matches from the table; the provided utility ExprHasName can help when needed, but FieldDecl name matching is more robust.
- Avoid overtainting:
  - Do not attempt alias tracking for member pointers in this minimal version; FieldRegions are stable and precise for this pattern.
- Keep the known release tables small and explicit:
  - Release-by-pointer: fput, blkdev_put, kfree, kvfree, put_device, filp_close (extendable).
  - Release-by-container: btrfs_close_bdev → members "bdev", "bdev_file" (extendable).

Chosen callbacks and their roles
- checkPostCall: recognize releases and mark regions as released (ReleasedSet/ReleasedOriginMap).
- checkBind: clear released state on any assignment to the region (covers reset to NULL and re-initialization).
- checkPreCall: warn on double release of already released regions.
- checkEndFunction: warn if member pointers released during this function were not set to NULL by function exit.

This plan yields:
- A precise warning at the misuse point (double release).
- A proactive warning at function exit for missing nullification (the exact fix performed in the patch by adding device->bdev_file = NULL;).
