Plan

1. Program state customizations
- REGISTER_MAP_WITH_PROGRAMSTATE(PublishedObjMap, const MemRegion*, const Stmt*)
  - Tracks objects that have been “published” to a user-visible ID registry within the current path. Key is the base MemRegion of the published object; value is the Stmt* of the publish call (for diagnostics).
- REGISTER_MAP_WITH_PROGRAMSTATE(AliasMap, const MemRegion*, const MemRegion*)
  - Tracks simple pointer aliases: maps a pointer variable’s region to the canonical “root” object region it aliases.
- REGISTER_SET_WITH_PROGRAMSTATE(AlreadyReportedSet, const MemRegion*)
  - Ensures we only report once per published object per path.

2. Helper utilities (internal to the checker)
- bool isIoctlOrCreateFunction(CheckerContext &C)
  - Fetch current function decl via C.getLocationContext()->getDecl(), and check the function name string. Return true if name contains “ioctl” or “create” (case-sensitive substring match).
  - This keeps the checker narrowly focused on ioctl-like creation routines to reduce false positives.
- Optional: const MemRegion* getRootAlias(const MemRegion *R, ProgramStateRef State)
  - Follow AliasMap chain transitively to the ultimate root region (if present), and return it.
- const MemRegion* getBaseObjectRegion(const MemRegion *R)
  - Strip field/element/var indirections to the most-derived object region (e.g., for a FieldRegion or ElementRegion, return its base object region). Use MemRegion APIs to walk up to the base.
- bool isPublishCall(const CallEvent &Call, unsigned &EntryParamIndex)
  - Return true if Call is one of:
    - xa_alloc, xa_alloc_cyclic (Entry param index = 2)
    - idr_alloc, idr_alloc_u32 (Entry param index = 1)
  - Use Call.getCalleeIdentifier()->getName() for matching (exact name).
- bool isGetRefLikeCall(const Expr *E, CheckerContext &C)
  - If E is a CallExpr, get callee spelling and check it contains “get” (e.g., “xe_file_get”, “kref_get”, “refcount_inc”, or “get_”). Use ExprHasName(E, "get", C). This is heuristic to report a crisper message when we detect a ref being taken after publish.

3. Callbacks and implementation details
- checkPostCall(const CallEvent &Call, CheckerContext &C) const
  - Gate: if !isIoctlOrCreateFunction(C), return.
  - If isPublishCall(Call, EntryParamIndex) is true:
    - Get SVal of the entry parameter: Call.getArgSVal(EntryParamIndex).
    - Get the MemRegion* MR = SVal.getAsRegion(); if null, return.
    - Canonicalize: Base = getBaseObjectRegion(getRootAlias(MR, State) or MR).
    - Insert (Base -> Call.getOriginExpr() or Call.getStmtForDiagnostics()) into PublishedObjMap in the state.
  - Rationale: record that “Base” object is now published; subsequent writes to its fields within the same function path are suspicious.
- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
  - Alias tracking (pointer-to-pointer assignments):
    - If Loc is a pointer-typed region (e.g., VarRegion) and Val is an SVal that holds a pointer to a region:
      - Let LHSReg = Loc.getAsRegion(), RHSReg = Val.getAsRegion().
      - Canonicalize RHSRoot = getBaseObjectRegion(getRootAlias(RHSReg, State) or RHSReg).
      - If both are non-null, set AliasMap[LHSReg] = RHSRoot.
  - Detect “write to published object after publish”:
    - If Loc denotes a memory write to a region under a base object (e.g., Loc is a FieldRegion/ElementRegion):
      - Base = getBaseObjectRegion(Loc.getAsRegion()).
      - Resolve Base = getRootAlias(Base, State) if present.
      - Look up PublishedObjMap[Base]; if present and Base not in AlreadyReportedSet:
        - Prepare a report. If the RHS (Val) is a call and isGetRefLikeCall(...) is true, use a specific message; else use a generic message.
        - Create a non-fatal error node and emit a PathSensitiveBugReport:
          - Title: “Object modified after publishing to ID registry”
          - Message (generic): “Published object is modified after xa/id allocation; publish must be the last step to prevent UAF race.”
          - Message (ref-specific): “Reference to owner/context is taken after publishing; publish must be last to prevent UAF race.”
          - Optionally, add a note range pointing to the earlier publish call using the Stmt* stored in PublishedObjMap.
        - Insert Base into AlreadyReportedSet to avoid duplicate reports.
- checkPreCall(const CallEvent &Call, CheckerContext &C) const
  - Optional conservative mutation detection via deref-known calls:
    - For each argument ArgI, if functionKnownToDeref(Call, DerefParams) returns true and ArgI in DerefParams:
      - Get ArgI’s region, canonicalize to Base via getBaseObjectRegion + getRootAlias.
      - If Base is in PublishedObjMap and not reported:
        - Report similarly as in checkBind, with generic message: “Object may be accessed/mutated after publishing; publish must be last.”
    - This is optional; include it but only trigger when functionKnownToDeref returns true to keep false positives low.
- checkBeginFunction(CheckerContext &C) const
  - No state needed here; we’ll check the function name ad-hoc in other callbacks.
- checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const
  - Clean up function-local tracking:
    - Clear PublishedObjMap, AliasMap, AlreadyReportedSet from state for this path (i.e., set to empty). This avoids state leaking between functions.
- checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const
  - Not necessary. We rely on checkBind for stores. You may skip this for simplicity.

4. Reporting details
- Use generateNonFatalErrorNode() to create the error node, then std::make_unique<PathSensitiveBugReport>.
- Keep message short and clear:
  - “Object modified after publishing via xa/id alloc; publish must be last to prevent UAF.”
- If available, add a note to the publish call site:
  - “Object published here” with a range from the saved Stmt* in PublishedObjMap.
- Only report once per object per path using AlreadyReportedSet.

5. Notes and heuristics to reduce false positives
- Restrict analysis to functions whose names contain “ioctl” or “create” to match the common entry points where objects are created and IDs are published.
- Only treat xa_alloc/xa_alloc_cyclic/idr_alloc/idr_alloc_u32 as publishing primitives. This keeps scope tight and aligned with the intended bug pattern.
- Focus on concrete field writes after publish (e.g., q->xef = ...). This directly matches the fixed pattern in the provided patch.
- Heuristic refinement for clarity: if the RHS of a post-publish write is a call whose name contains “get”, use the more specific message about “taking reference after publishing.”

6. Minimal use of provided utility functions
- ExprHasName: detect “get” in RHS calls to refine the message.
- functionKnownToDeref: optional enhancement in checkPreCall to flag calls that dereference the published object.
- findSpecificTypeInParents / findSpecificTypeInChildren: not required for this plan.
- getMemRegionFromExpr: not required; we access regions from SVals already.

7. Summary of detection logic
- Record when an object pointer is published to an ID registry (xa/id alloc).
- After that point, any write to the object’s fields within the same function path indicates the publish wasn’t the last step → warn.
- Optionally, calls known to dereference the object after publish are also suspicious → warn.
- This models the race where another ioctl could find and free the object after it is published, while the creator still mutates it, causing UAF.
