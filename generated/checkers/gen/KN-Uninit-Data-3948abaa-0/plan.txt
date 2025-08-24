1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(UninitBufMap, const MemRegion*, bool)
  - Tracks heap buffers that may contain uninitialized bytes. Insert on kmalloc, remove on kzalloc/full-zero and on free.
- REGISTER_MAP_WITH_PROGRAMSTATE(AllocByteSizeMap, const MemRegion*, uint64_t)
  - Remembers the allocation size in bytes when it can be resolved to a constant.
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer aliases; when p2 = p1, record p2 -> p1 so queries can resolve to the canonical region.

Helper utilities to add
- static const MemRegion* getBase(const MemRegion *R) to return R ? R->getBaseRegion() : nullptr.
- static const MemRegion* resolveAlias(const MemRegion *R, ProgramStateRef S) to chase PtrAliasMap (with a small loop cap) and return the canonical base region.
- static bool calleeNameContains(const CallEvent &Call, StringRef Needle) to robustly match functions (return false if no callee identifier).
- Optionally recognize builtin memset: if (!ID) use Call.getKind()/Call.getOriginExpr callee to check Builtin::BI_memset or BI__builtin_memset if available; otherwise rely on name match.

2) Callback selection and behavior

A) checkPostCall (track allocations and zero-inits)

- kmalloc:
  - if calleeNameContains(Call, "kmalloc") and NOT calleeNameContains(Call, "kzalloc"):
    - SVal Ret = Call.getReturnValue(); if Region = Ret.getAsRegion(), let Base = getBase(Region).
    - Mark Base in UninitBufMap with true.
    - Try to evaluate the size argument (arg 0) to integer using EvaluateExprToInt. If success, store its uint64_t value in AllocByteSizeMap[Base]. Otherwise, erase any prior entry for Base in AllocByteSizeMap (unknown size).
- kzalloc:
  - if calleeNameContains(Call, "kzalloc"):
    - Retrieve Base from return value as above.
    - Remove Base from UninitBufMap (it’s fully zeroed).
    - Try to evaluate arg 0; if success store size in AllocByteSizeMap[Base], else erase size.
- memset zeroing (optional but recommended to reduce false positives):
  - if calleeNameContains(Call, "memset") OR builtin memset detected:
    - Extract dest pointer (arg 0) region: const MemRegion *R = getMemRegionFromExpr(arg0, C); let Base = resolveAlias(getBase(R), State).
    - Extract value (arg 1); require it be constant zero (EvaluateExprToInt == 0).
    - Extract len (arg 2) as integer if possible.
    - If Base is in UninitBufMap:
      - If AllocByteSizeMap has a known size S and memset len M is known and M >= S, then remove Base from UninitBufMap (fully zeroed).
      - Otherwise, do nothing (do not mark safe on partial/unknown memset).
- kcalloc/kvzalloc (optional):
  - If you want to reduce FPs further, treat kcalloc/kvzalloc like kzalloc: mark as zeroed and try to compute total size (nmemb * size); if both are constant and multiplication fits uint64_t, store it; otherwise erase size.

B) checkPreCall (detect copy_to_user and frees)

- copy_to_user detection:
  - if calleeNameContains(Call, "copy_to_user"):
    - Get the source argument (arg 1) region: const MemRegion *R = getMemRegionFromExpr(arg1, C); Base = resolveAlias(getBase(R), State).
    - If Base is in UninitBufMap:
      - Optionally reduce FPs when sizes are known:
        - If AllocByteSizeMap[Base] is known (S) and the third argument (len) can be evaluated to M, and M < S, skip report (only a subset is copied).
        - Otherwise (len unknown or M >= S or no size available), report a bug.
      - Emit report:
        - Node = C.generateNonFatalErrorNode()
        - Message: "copy_to_user from kmalloc() buffer may leak uninitialized bytes; use kzalloc() or clear the buffer."
        - Highlight the source argument expression.
- Free (cleanup):
  - If calleeNameContains(Call, "kfree") OR calleeNameContains(Call, "kvfree"):
    - Extract arg 0 region Base = resolveAlias(getBase(getMemRegionFromExpr(arg0, C)), State).
    - Erase Base from UninitBufMap and AllocByteSizeMap.

C) checkBind (track aliases)

- When a pointer is stored into another pointer:
  - If Loc corresponds to a pointer-typed variable region LBase and Val is a region VBase (both via getMemRegionFromExpr-like logic on the Stmt/SVals), add PtrAliasMap[LBase] = VBase.
  - If Val is nonloc::ConcreteInt(0), you may choose to erase alias for LBase (no alias).
  - Do not modify UninitBufMap here. Only alias map is updated.

D) checkRegionChanges (robust cleanup)

- For any ExplicitRegions/Regions invalidated, erase those base regions from UninitBufMap, AllocByteSizeMap, and remove any alias entries that either map to them or originate from them.

3) Notes on expression/region handling and heuristics

- Always normalize to base region and then through resolveAlias before querying maps to survive pointer arithmetic, field/element regions, and simple aliases.
- Only treat memset as full zeroing if both memset length and allocation size are known and len >= size (use EvaluateExprToInt).
- To reduce false positives, if the copy_to_user length is provably smaller than the known allocation size (M < S), skip the warning (caller may be copying only the initialized prefix).
- No attempt is made to infer partial initialization from field writes; keep the checker simple and robust.

4) Bug reporting

- Create a single BugType, e.g., "Kernel info leak (copy_to_user)" at checker construction.
- Report with a short message: "copy_to_user from kmalloc() buffer may leak uninitialized bytes"
- Use std::make_unique<PathSensitiveBugReport> with the call expression site as the location. Highlight the source (arg 1) expression of copy_to_user.

5) Summary of the minimal end-to-end flow

- kmalloc -> mark region uninitialized (+remember size if constant).
- kzalloc/kcalloc/kvzalloc or memset(ptr, 0, len >= alloc-size) -> mark initialized (safe).
- Track aliases via checkBind so that using another pointer name still points to the same base.
- On copy_to_user(src, len): if src (after alias resolution) is still marked uninitialized, warn (unless len is known smaller than alloc-size).
- Clean up on kfree/kvfree and on region invalidations.
