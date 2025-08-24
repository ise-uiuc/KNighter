Plan

1) Program state customizations
- REGISTER_MAP_WITH_PROGRAMSTATE(ResourceStateMap, const MemRegion *, unsigned)
  - States:
    - 0 = Unknown/not tracked
    - 1 = Allocated (owns a live resource)
    - 2 = MaybeFreed (a helper that may free was called)
    - 3 = Freed (definitely freed)
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)
  - Tracks simple pointer-to-pointer aliases (dst -> canonical root region).
- Helpers:
  - const MemRegion *getRootAlias(ProgramStateRef S, const MemRegion *R): chase PtrAliasMap until fixpoint to get canonical root.
  - ProgramStateRef setAlias(ProgramStateRef S, const MemRegion *Dst, const MemRegion *SrcRoot).
  - Optional: ProgramStateRef clearAlias(ProgramStateRef S, const MemRegion *Dst).
  - unsigned getResState(ProgramStateRef S, const MemRegion *R): read state from ResourceStateMap for root region, default 0.
  - ProgramStateRef setResState(ProgramStateRef S, const MemRegion *R, unsigned NewState): write state for root region.
  - Small helpers to identify callee by name:
    - bool isAllocCall(const CallEvent &Call): callee is "fastrpc_buf_alloc" or "fastrpc_remote_heap_alloc".
    - bool isFreeCall(const CallEvent &Call): callee is "fastrpc_buf_free".
    - bool isMaybeFreeCall(const CallEvent &Call): callee is "fastrpc_req_munmap_impl".
  - Extract target pointer variable’s MemRegion from a call argument:
    - Use getMemRegionFromExpr(Call.getArgExpr(Idx), C) and then canonicalize via getRootAlias.

2) Callbacks to use and how to implement

A) checkPostCall (model allocations and state transitions after calls)
- Purpose:
  - Mark the out-parameter as Allocated after alloc calls.
  - Mark the target pointer as MaybeFreed after maybe-free helper calls.
  - Mark the target pointer as Freed after direct free calls.
- Steps:
  1) If isAllocCall(Call):
     - Determine the index of the out-parameter (for both fastrpc_buf_alloc and fastrpc_remote_heap_alloc it is the 4th parameter: index 3).
     - Get MR = getMemRegionFromExpr(Call.getArgExpr(3), C). If null, bail.
     - Root = getRootAlias(State, MR).
     - State = setResState(State, Root, 1 /*Allocated*/).
     - C.addTransition(State).
  2) If isMaybeFreeCall(Call):
     - The buffer is the 2nd parameter: index 1 (fastrpc_req_munmap_impl(fl, buf)).
     - Get MR from arg1, Root, then:
       - If getResState(State, Root) == 1 (Allocated), set to 2 (MaybeFreed).
       - Else, if Unknown, still set to MaybeFreed to be conservative (helps detect the “may free then free again” pattern).
     - C.addTransition(State).
  3) If isFreeCall(Call):
     - The buffer is the first parameter: index 0 (fastrpc_buf_free(buf)).
     - Get MR from arg0, Root.
     - After the call returns, if no report was emitted (see checkPreCall), mark Freed:
       - State = setResState(State, Root, 3 /*Freed*/).
     - C.addTransition(State).

B) checkPreCall (detect double free before executing the second free)
- Purpose: Warn when calling fastrpc_buf_free on a pointer that has already been freed or may have been freed by a helper.
- Steps:
  1) If !isFreeCall(Call), return.
  2) MR = getMemRegionFromExpr(Call.getArgExpr(0), C); if null, return.
  3) Root = getRootAlias(State, MR).
  4) St = getResState(State, Root).
  5) If St == 2 /*MaybeFreed*/ or St == 3 /*Freed*/:
     - Generate a non-fatal error node and emit a PathSensitiveBugReport with a short message:
       - “Double free: resource may have been released earlier in error path”
     - Optionally, add a note range on the earlier call site (if you recorded it); otherwise, keep the report minimal.
  6) Do not change state here; state change to Freed will be done in checkPostCall.

C) checkBind (track pointer aliasing)
- Purpose: If code does p2 = p1; treat p2 as an alias of p1, so frees via either name are correlated.
- Steps:
  1) If Loc is a MemRegion of a pointer variable (cast to MemRegion) and Val is an SVal referring to another pointer variable’s MemRegion:
     - SrcMR = Val.getAsRegion(); DstMR = Loc.getAsRegion(); if either null, return.
     - RootSrc = getRootAlias(State, SrcMR).
     - State = setAlias(State, DstMR, RootSrc).
  2) If Val is a concrete 0 (null):
     - Optionally, clear alias for DstMR (clearAlias) to avoid propagating freed/alloc state spuriously through nullification. This is optional; simplest is to do nothing.

D) checkEndFunction
- Purpose: Clean up to avoid leaking state across functions.
- Steps:
  - Drop all entries from ResourceStateMap and PtrAliasMap by returning State->remove<ResourceStateMap>().remove<PtrAliasMap>().

3) Heuristics and constraints to reduce false positives
- Only transition to MaybeFreed on isMaybeFreeCall when the argument region is known (has a region) and has been previously Allocated or is Unknown. This better matches the pattern where a helper may release a previously allocated buffer.
- Report only when the later free call targets a tracked region (appeared in ResourceStateMap). If the region was never tracked (i.e., not observed via alloc), do not report.
- Keep the checker narrowly scoped by function names:
  - Allocators: "fastrpc_buf_alloc", "fastrpc_remote_heap_alloc"
  - Maybe-free helper: "fastrpc_req_munmap_impl"
  - Free: "fastrpc_buf_free"
- If needed, allow easy extension via small arrays of names so users can add more alloc/free pairs.

4) Where to use provided utility functions
- getMemRegionFromExpr: to obtain MemRegion of both &buf (out-param for alloc) and buf (argument of free/maybe-free).
- ExprHasName: not strictly needed here.
- findSpecificTypeInParents/Children: not needed.
- EvaluateExprToInt/inferSymbolMaxVal: not needed in the simplest version.

5) Bug reporting
- Use generateNonFatalErrorNode to create a node.
- Create a PathSensitiveBugReport with a concise message:
  - Title: “Double free of resource”
  - Description: “Second free after earlier helper may have already released ‘buf’”
- Attach the current call expression as the location. If practical, track and note the earlier maybe-free call site by storing a ProgramPoint or SourceRange in the state when setting MaybeFreed; otherwise, keep the report minimal as required.

6) Summary of the detection for the target patch
- After alloc call → ResourceStateMap[buf] = Allocated.
- On error path, call fastrpc_req_munmap_impl(fl, buf) → ResourceStateMap[buf] = MaybeFreed.
- Then falling through to the shared label calling fastrpc_buf_free(buf) → checkPreCall sees MaybeFreed and reports “Double free,” matching the original bug.
