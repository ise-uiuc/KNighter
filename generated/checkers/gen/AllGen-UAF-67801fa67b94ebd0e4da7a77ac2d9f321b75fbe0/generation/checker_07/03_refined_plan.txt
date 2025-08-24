1) Program state

- REGISTER_SET_WITH_PROGRAMSTATE(PublishedObjs, const MemRegion *)
  - Tracks the pointee regions of objects that have been inserted into a globally visible ID map (i.e., “published”) in the current path.

- REGISTER_MAP_WITH_PROGRAMSTATE(PublishedSite, const MemRegion *, const Stmt *)
  - Remembers the publishing call statement for each published object to improve diagnostics (point back to xa_alloc/idr_alloc site).


2) Target functions and key arguments

- Maintain a small, fixed table of “publishers” and which parameter is the object being published:
  - xa_alloc(table, idp, entry, limit, gfp) -> entry is param index 2
  - xa_insert(table, index, entry, gfp) -> entry is param index 2
  - xa_store(table, index, entry, gfp) -> entry is param index 2
  - idr_alloc(idr, ptr, start, end, gfp) -> ptr is param index 1
  - idr_alloc_cyclic(idr, ptr, start, end, gfp) -> ptr is param index 1
  - idr_replace(idr, ptr, id) -> ptr is param index 1

Note: Prefer to start with xa_alloc and idr_alloc to reduce noise; you can extend easily.


3) Callback selection and behavior

A) checkPostCall (mark object as published)

- Goal: When we see a call to a known publisher, mark the pointee region passed in as “published”.
- Steps:
  1. Identify calls by callee name; match against the “publishers” table (string compare via Call.getCalleeIdentifier()->getName()).
  2. Fetch the “entry” argument expression by the configured param index for that callee.
  3. Get the MemRegion of the pointee using getMemRegionFromExpr on that argument expression.
     - This should give the region the pointer value points to (not the VarRegion of the local pointer variable).
     - If it’s null, skip (cannot reason).
  4. Add that region to PublishedObjs and record the origin statement in PublishedSite (use Call.getOriginExpr()).
  5. No path pruning is necessary; subsequent code commonly guards on the return value (err), and the analyzer will only reach later statements on success paths.

Why here: The object becomes globally reachable exactly at this call, so any following mutation to the object’s memory is a potential race/UAF hazard.


B) checkBind (detect writes to published objects)

- Goal: Flag any store into memory that belongs to a “published” object.
- Steps:
  1. For each bind, take Loc (the destination) and extract its MemRegion (if not a MemRegion, skip).
  2. Ascend the region chain to its base region (walk through FieldRegion/ElementRegion/CXXBaseObjectRegion/etc. via getSuperRegion until reaching a non-SubRegion). Keep both the full region and base.
  3. Check whether the destination region is the same as, or a subregion of, any region in PublishedObjs:
     - Use region->isSubRegionOf(PublishedRegion) or manual upward walk to compare.
  4. If yes, this is a write-after-publish.
     - Emit a bug:
       - Create a non-fatal error node.
       - Message: “Object published to ID map before full init; write to object occurs after xa_alloc/idr_alloc (possible UAF race). Make publish the last step.”
       - Attach a note to the publisher site (from PublishedSite map) like “Object published here” using the stored Stmt pointer.
       - Optionally, add a note at the current store site “Write to published object happens here”.
  5. Do not remove the object from PublishedObjs; you want to catch all subsequent writes on this path.

Why checkBind: Field assignments (e.g., q->xef = ...) lower to stores into FieldRegion/ElementRegion under the pointee region of q. This catches the core shape of the bug (post-publish field initialization).


C) checkPostCall (optional: detect mutating calls after publish)

- Goal: Catch potential mutations via function calls that dereference the published object’s pointer (not only direct stores).
- Steps:
  1. For every call, collect its arguments.
  2. For each argument:
     - If it is a pointer-typed Expr, get its MemRegion via getMemRegionFromExpr.
     - If this region equals or is a subregion of any region in PublishedObjs, then the call may mutate the published object.
     - Use functionKnownToDeref(Call, DerefParams) to reduce false positives: only warn if the argument index is known to be dereferenced by the callee. If no knowledge, you may skip to avoid noise.
  3. If matched, report similarly to checkBind:
     - “Object published to ID map before full init; function call may mutate object after publication (possible UAF race). Make publish the last step.”
     - Add a note to the publisher site.

This is optional but useful to catch patterns where post-publish changes happen via helper functions.


4) Utilities and helpers to use

- getMemRegionFromExpr: to obtain the pointee MemRegion from an argument expression of pointer type, both when publishing and when checking later calls.
- findSpecificTypeInParents / findSpecificTypeInChildren: not strictly needed; avoid to keep the checker simple.
- functionKnownToDeref: use in the optional post-call mutation detection to reduce false positives.
- ExprHasName: not required here.

Helper routine: getBaseRegion(const MemRegion *R)
- Walk R via getSuperRegion until reaching the topmost non-SubRegion. Use this in subregion checks and comparisons.


5) Reporting details

- Use a single BugType stored as a checker member: “Early publication to ID map (possible UAF)”.
- On first offending store or dereferencing call after publication:
  - Generate node with generateNonFatalErrorNode.
  - Use std::make_unique<PathSensitiveBugReport>.
  - Main message (short and clear): “Published object to ID map before full initialization; later write may race with destroy (UAF). Move xa_alloc/idr_alloc to the end.”
  - Add note referencing the publishing call site using the stored Stmt from PublishedSite: “Object published here”.
  - Optionally, note the specific field write or dereferencing call site.


6) Callback summary

- checkPostCall:
  - If callee is in PublisherSet, mark pointee region as published in PublishedObjs and store origin Stmt in PublishedSite.
  - Optionally, also detect mutations via functionKnownToDeref for calls after publication.

- checkBind:
  - For every store, if destination region is equal to or nested under any published region, report.

- No other callbacks are required. Program state will naturally reset across functions.


7) False positive control

- Only mark publication when we can extract a valid pointee region from the entry argument.
- Focus primary diagnostics on direct stores (checkBind). These are high-confidence.
- Keep the post-call mutation detection behind functionKnownToDeref to avoid noise.
- Do not attempt to guess success/failure of the publisher call; the analyzer’s path-sensitivity will ensure that stores reached after the typical “if (err) goto …” check lie on success paths.
