Plan

1. Program state
- REGISTER_SET_WITH_PROGRAMSTATE(ZeroInitObjs, const MemRegion*)
  - Tracks heap objects known to be zero-initialized (kzalloc/kcalloc/etc).
- REGISTER_SET_WITH_PROGRAMSTATE(InitCountSet, std::pair<const MemRegion*, const FieldDecl*>)
  - Tracks, per object, which __counted_by count fields have been initialized (written) since allocation.
- Notes:
  - Key for InitCountSet is a pair (BaseObjRegion, CountFieldDecl). This allows multiple counted_by fields per object if needed.
  - When a new zero-initialized object is detected, we add it to ZeroInitObjs; we do not need to pre-populate InitCountSet.

2. Helper utilities
- isZeroInitAllocator(const CallEvent &Call)
  - Returns true if callee name is one of: "kzalloc", "kcalloc", "kvzalloc", "vzalloc", "devm_kzalloc", "devm_kcalloc".
- isMemcpyLike(const CallEvent &Call)
  - Returns true if callee name is one of: "memcpy", "memmove".
- getFieldRegionAndBase(const Expr *E, CheckerContext &C, const FieldRegion* &FR, const MemRegion* &BaseReg)
  - Use getMemRegionFromExpr(E, C). If it’s a FieldRegion, set FR to it and BaseReg to FR->getSuperRegion() with casts stripped.
  - If not, try to find a MemberExpr inside E via findSpecificTypeInChildren<MemberExpr>(E) and repeat on that Expr.
  - Return false if we cannot resolve a FieldRegion.
- getCountFieldForFlexArray(const FieldDecl *FlexFD, const FieldDecl* &CountFD)
  - If FlexFD has an IncompleteArrayType (flexible array) and has CountedByAttr, return the FieldDecl referenced by the attribute as CountFD. Otherwise return false.
- isCountFieldInRecord(const FieldDecl *FD)
  - For FD->getParent() (RecordDecl), iterate fields; if any field has CountedByAttr referencing FD, return true. This lets us recognize writes to the counting field in checkBind, without needing the flexible array reference at that point.
- stripCasts(const MemRegion *R)
  - Use Region methods to strip cast regions, keeping the base TypedValueRegion/HeapRegion to use as object key.
- sizeExprIsDefinitelyZero(const Expr *SizeArg, CheckerContext &C)
  - Use EvaluateExprToInt; if constant equals 0, return true. Else false.
- sizeExprMayBeNonZero(const Expr *SizeArg, CheckerContext &C)
  - If EvaluateExprToInt returns a constant > 0, return true.
  - Else, if SizeArg involves a symbol, use inferSymbolMaxVal on that symbol; if maxVal > 0, return true.
  - Otherwise, return true conservatively (to avoid missing the pattern), unless you prefer to be stricter.

3. Callbacks

3.1 checkPostCall
- Zero-initialization tracking:
  - If isZeroInitAllocator(Call):
    - const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
    - If RetReg is non-null, add RetReg to ZeroInitObjs.
    - Optionally, remove any (RetReg, *) entries from InitCountSet if you perform cleanup; otherwise no action is necessary because the allocation introduces a fresh region.
- No other work here is needed.

3.2 checkBind
- Detect writes to counted_by count fields and mark initialized:
  - Loc is the destination location. If !Loc.getAsRegion(), return.
  - If Region is a FieldRegion FR:
    - const FieldDecl *FD = FR->getDecl();
    - If not isCountFieldInRecord(FD), return.
    - const MemRegion *BaseReg = stripCasts(FR->getSuperRegion()).
    - Insert the pair (BaseReg, FD) into InitCountSet.
- Do not try to propagate aliases; for this pattern, we use the FieldRegion’s super-region which refers directly to the pointee object, independent of pointer aliases.

3.3 checkPreCall
- Detect copy into a counted_by flexible array before initializing the count field:
  - If not isMemcpyLike(Call), return.
  - const Expr *DstExpr = Call.getArgExpr(0).
  - Resolve FieldRegion for destination:
    - const FieldRegion* FR; const MemRegion* BaseReg;
    - If getFieldRegionAndBase(DstExpr, C, FR, BaseReg) == false, return.
  - Validate that destination field is a counted_by flexible array:
    - const FieldDecl *FlexFD = FR->getDecl();
    - Check FlexFD->getType()->isIncompleteArrayType().
    - Fetch CountFD via getCountFieldForFlexArray(FlexFD, CountFD). If not found, return.
  - Check object allocation/zero-init origin:
    - BaseReg = stripCasts(BaseReg).
    - If BaseReg not in ZeroInitObjs, return (reduces false positives to the intended pattern where the object was zeroed and the count is 0).
  - Check whether the counting field was initialized:
    - If InitCountSet does not contain (BaseReg, CountFD), then the count field has not been written since allocation.
  - Optionally suppress when copy size is definitely 0:
    - const Expr *SizeExpr = Call.getArgExpr(2).
    - If sizeExprIsDefinitelyZero(SizeExpr, C) is true, return (no bug).
    - Otherwise continue (or make it stricter using sizeExprMayBeNonZero).
  - Report:
    - Create an error node with generateNonFatalErrorNode.
    - Emit a PathSensitiveBugReport with a short message:
      - "Copy into __counted_by array before initializing its count field"
    - Add source ranges for the destination argument and optionally a note for the allocator call site if available via bug report visitors.

4. Rationale and behavior
- The checker models the common kernel pattern: kzalloc initializes the object to zero; counted_by uses the count field to compute the flexible array’s runtime bound for fortified operations. A memcpy into the array prior to writing the count field triggers FORTIFY as buffer size is computed as 0.
- By:
  - tracking zero-initialized heap regions,
  - identifying counted_by flexible array destinations in memcpy/memmove,
  - and ensuring a write to the corresponding count field occurred beforehand,
  the checker flags only the intended misordering bug.
- Pointer aliasing is not needed because we resolve the FieldRegion’s super-region (the pointee object) from the destination expression itself.
- False positive minimization:
  - Requires the object be known zero-initialized (kzalloc/kcalloc/...).
  - Optionally requires copy size to be possibly non-zero.
- This directly catches the target pattern in thermal_zone_device_register_with_trips: kzalloc of tz, memcpy into tz->trips, then setting tz->num_trips afterward.
