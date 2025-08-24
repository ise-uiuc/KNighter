1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitObjMap, const MemRegion*, bool)
  - Key: the base MemRegion of a heap-allocated struct (the object).
  - Value: CounterSet flag (false initially). Set to true once a counted_by counter field of this object is written.

No other custom state is required.

2) Helper predicates/utilities

Implement small helpers (pure functions) used from callbacks:

- isZeroingAllocator(const CallEvent &Call):
  - Return true if callee name is one of: "kzalloc", "kcalloc", "kzalloc_array", "devm_kzalloc", "devm_kcalloc".
- isMemWriteCall(const CallEvent &Call):
  - Return true if callee name is in: "memcpy", "memmove", "memset", "copy_from_user".
- getBaseRegion(const MemRegion *R):
  - Walk up super regions until you reach the first non-Field/Element region representing the base object (e.g., heap region/VarRegion).
- getFieldRegionFromExpr(const Expr *E, CheckerContext &C):
  - Use getMemRegionFromExpr(E, C) to get a region. If it’s an ElementRegion, go to its super region. Return the FieldRegion if found, otherwise nullptr.
- isFlexibleArrayWithCountedBy(const FieldDecl *FD, const FieldDecl *&CounterFD):
  - Return true if:
    - FD->getType() is an IncompleteArrayType (flexible array).
    - FD has CountedByAttr (or equivalent). If available, extract the referenced counter FieldDecl into CounterFD. If the API does not expose the referenced FieldDecl, it’s sufficient to know that the field is counted_by; in that case set CounterFD to nullptr and just treat it as counted_by present.
- isCounterFieldForAnyCountedBy(const FieldDecl *FD):
  - Obtain the RecordDecl* RD = FD->getParent().
  - Iterate RD->fields(); if any field GF has CountedByAttr that references FD, return true.
- getBaseRegionForField(const FieldRegion *FR):
  - Return getBaseRegion(FR->getSuperRegion()).

3) checkPostCall: track zero-initialized allocations

- If isZeroingAllocator(Call):
  - SVal Ret = Call.getReturnValue().
  - If const MemRegion *MR = Ret.getAsRegion():
    - State = State->set<ZeroInitObjMap>(MR, false) to mark object as zeroed and its counted_by counter not set yet.

4) checkBind: detect initialization of the counted_by counter

- If Loc is a location and can be converted to a FieldRegion FR:
  - const FieldDecl *FD = FR->getDecl().
  - If isCounterFieldForAnyCountedBy(FD) returns true:
    - const MemRegion *Base = getBaseRegionForField(FR).
    - If Base exists in ZeroInitObjMap, set its value to true (CounterSet = true).
  - Note: We do not need to inspect the assigned value; any write counts as “initialized” for this checker’s purpose.

5) checkPreCall: flag writes to counted_by flexible arrays before counter init

- If isMemWriteCall(Call):
  - const Expr *DestE = Call.getArgExpr(0).
  - const FieldRegion *FR = getFieldRegionFromExpr(DestE, C).
  - If FR is null, return.
  - const FieldDecl *FD = FR->getDecl(); const FieldDecl *CounterFD = nullptr;
  - If !isFlexibleArrayWithCountedBy(FD, CounterFD), return.
  - const MemRegion *Base = getBaseRegionForField(FR).
  - Lookup Base in ZeroInitObjMap:
    - If present and value == false (counter not set yet):
      - Report a bug at DestE: "Flex-array write before counter init (__counted_by)".
      - Optionally set the map entry to true to suppress duplicate reports along the same path.

6) checkLocation: catch direct stores into the flexible array (not via calls)

- If IsLoad == false:
  - If Loc is a location and has a MemRegion R:
    - Walk up R’s super regions to find a FieldRegion FR if any.
    - If FR exists and is a flexible array with counted_by (same check as above):
      - const MemRegion *Base = getBaseRegionForField(FR).
      - If Base is in ZeroInitObjMap with value == false:
        - Report: "Flex-array write before counter init (__counted_by)".

7) Bug reporting

- Create a PathSensitiveBugReport with a short message: "Flex-array write before counter init (__counted_by)".
- Point the primary location to the destination expression (for calls) or the store statement (for checkLocation).
- Use generateNonFatalErrorNode to create the error node.
- Do not produce fix-its.

8) Notes to reduce false positives

- Only warn when the base object is known to come from a zero-initializing allocator (tracked in ZeroInitObjMap). This matches the kernel pattern where the counter is zero after kzalloc/kcalloc.
- We do not attempt to prove the counter’s runtime value; only that it was assigned at least once before the first write to the flexible array.
- If CountedByAttr access is unavailable in the build environment, keep the flexible-array requirement (IncompleteArrayType) and still require that some counter field in the same record is written before the write. If you cannot relate the exact counter field, restrict to fields named "datalen" only as a conservative fallback to avoid false positives.

9) Summary of callbacks used

- checkPostCall: mark zero-initialized allocations (ZeroInitObjMap[Base] = false).
- checkBind: flip to true on writes to the counter field (if the field is counter for any counted_by flex-array in the same record).
- checkPreCall: report when memcpy/memmove/memset/copy_from_user target a counted_by flexible array of a tracked object whose counter is not yet set.
- checkLocation: report on direct stores into counted_by flexible arrays of tracked objects.

This is the minimal, path-sensitive flow to detect "copying into a __counted_by flexible array before initializing its counter" as in the target patch.
