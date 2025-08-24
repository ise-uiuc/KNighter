1) Program State

- REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitObjMap, const MemRegion*, bool)
  - Tracks base object regions that are known to be zero-initialized (e.g., from kzalloc/kcalloc/kvzalloc/vzalloc). Value is always true; presence in the map means “this object is zeroed”.

- REGISTER_MAP_WITH_PROGRAMSTATE(CounterInitMap, const MemRegion*, bool)
  - Tracks whether a specific counter field (the field referenced by __counted_by) in a specific object has been initialized. The key must be the FieldRegion of the counter field (i.e., base object + the counter FieldDecl). Value true means initialized.

No alias maps are strictly needed if we derive the base object region directly from the MemberExpr of the flexible-array member.


2) Helper Routines

- bool isZeroingAlloc(const CallEvent &Call)
  - Return true for known zero-initializing allocators: kzalloc, kcalloc, kzalloc_array, kvzalloc, vzalloc.

- bool isWriteToFirstParamFunction(const CallEvent &Call)
  - Return true for functions that write to their first argument: memcpy, __memcpy, memmove, copy_from_user. Keep scope minimal to avoid noise.

- const FieldDecl *getCountedByCounterField(const FieldDecl *FAMField)
  - If FAMField has the counted_by attribute, return the FieldDecl of the counter field. Use FAMField->hasAttr<CountedByAttr>() and attr->getParam() to retrieve the referenced field; resolve that to a FieldDecl within the same RecordDecl. If that API is not present, conservatively bail (no warning).

- bool isCounterForAnyCountedByField(const FieldDecl *FD)
  - Scan FD->getParent()’s fields; if any flexible-array member field has counted_by(FD), return true. Used in checkBind to avoid marking unrelated fields.

- const MemRegion *getBaseRegionFromMember(const MemberExpr *ME, CheckerContext &C)
  - For ME referring to “obj->data”, return the base object region for “obj”. Use getMemRegionFromExpr(ME->getBase()).

- const FieldRegion *getFieldRegionFor(const MemRegion *Base, const FieldDecl *FD, CheckerContext &C)
  - Using the RegionManager from the ProgramState, build a FieldRegion for the given FD on top of the Base (cast Base to a suitable TypedValueRegion/DeclRegion if needed). This uniquely identifies “obj->counter” for this particular object.


3) Callbacks and Logic

A) checkPostCall
- Purpose: Mark newly created objects as zero-initialized when returned from zeroing allocators.
- Steps:
  1. If !isZeroingAlloc(Call), return.
  2. Obtain the return SVal: SVal Ret = Call.getReturnValue();
  3. Get the pointee region: const MemRegion *ObjR = Ret.getAsRegion(); If null, return.
  4. State = State->set<ZeroInitObjMap>(ObjR, true);
  5. C.addTransition(State).
- Notes: We only need to know the region is zeroed; specific counters are initially not in CounterInitMap.

B) checkBind
- Purpose: Detect explicit initialization of the counter field (e.g., obj->len = n;).
- Steps:
  1. Extract the destination location’s region: const MemRegion *R = Loc.getAsRegion(); If null, return.
  2. If R is not a FieldRegion, return.
  3. const FieldDecl *FD = cast<FieldRegion>(R)->getDecl();
  4. If !isCounterForAnyCountedByField(FD), return.
  5. Mark this counter field as initialized: State = State->set<CounterInitMap>(R, true);
  6. C.addTransition(State).
- Notes: We only mark when the field is a known counter for some counted_by flexible array. We do not need to check the value assigned.

C) checkPreCall
- Purpose: Before a write call like memcpy/memmove/copy_from_user, ensure that writes to a flexible-array member annotated with __counted_by happen only after its counter is initialized.
- Steps:
  1. If !isWriteToFirstParamFunction(Call), return.
  2. Expr *DstArg = Call.getArgExpr(0); Find the flexible-array member in DstArg:
     - Try dyn_cast<MemberExpr>(DstArg->IgnoreParenCasts()).
     - If null, call findSpecificTypeInChildren<MemberExpr>(DstArg). If still null, return.
  3. const MemberExpr *ME = ...
     - const FieldDecl *FAMField = dyn_cast<FieldDecl>(ME->getMemberDecl()); If null, return.
     - Ensure it is a flexible-array member: FAMField->getType()->isIncompleteArrayType(). If false, return.
     - Ensure it has counted_by: FAMField->hasAttr<CountedByAttr>(). If false, return.
  4. Retrieve the counter FieldDecl: const FieldDecl *CounterFD = getCountedByCounterField(FAMField); If null, return.
  5. Get base object region: const MemRegion *BaseR = getBaseRegionFromMember(ME, C); If null, return.
  6. Check if this object is known zero-initialized: if (!State->contains<ZeroInitObjMap>(BaseR)) return; Only warn for zero-initialized objects (the concrete bug pattern).
  7. Build the FieldRegion for the counter: const FieldRegion *CounterFR = getFieldRegionFor(BaseR, CounterFD, C); If null, return.
  8. If State->lookup<CounterInitMap>(CounterFR) is not true:
     - Generate a non-fatal error node: ExplodedNode *N = C.generateNonFatalErrorNode();
     - Emit a PathSensitiveBugReport with message like:
       "Write to flexible array before setting its __counted_by counter"
       Optionally include names: "Writing to ‘<FAMField->getNameAsString()>’ before initializing ‘<CounterFD->getNameAsString()>’".
     - C.emitReport(...)
- Notes: This directly flags the brcmfmac bug where memcpy(event->data, ...) precedes event->datalen = datalen; after kzalloc zeroed the object.

D) (Optional) checkLocation
- Purpose: Catch direct stores into the flexible-array member, e.g., obj->data[i] = ...;.
- Steps:
  1. If IsLoad, return.
  2. If Loc is an ElementRegion whose super-region is a FieldRegion FR on a flexible-array member with counted_by, then apply the same logic as in checkPreCall:
     - Obtain BaseR from FR->getSuperRegion(), obtain FAMField and CounterFD, build CounterFR, and check ZeroInitObjMap[BaseR] and CounterInitMap[CounterFR]. If zero-initialized and not initialized counter, report.


4) Additional Details

- How to find the counter from the attribute:
  - Use FAMField->getAttr<CountedByAttr>()->getParam() to obtain the referenced expression, then resolve to a FieldDecl within the same RecordDecl. If resolution is not straightforward or the attribute API differs, fall back to scanning the RecordDecl fields for a name match with ExprHasName.

- Minimizing false positives:
  - Only warn if the base object is known zero-initialized (via kzalloc/kcalloc/etc.) and the specific counter field for the flexible array has not been marked initialized on the current path.
  - Do not warn if we fail to resolve regions or the counted_by relation.

- Bug type:
  - Keep a single BugType member: "Counted-by flexible array write before counter init".
  - Short message as required: "Write to flexible array before setting its __counted_by counter".


5) Summary of the Flow for the Target Patch

- PostCall on kzalloc marks ‘event’ object region as zero-initialized.
- PreCall on memcpy detects first argument is event->data, confirms it is a flexible array with counted_by(datalen), finds base region (event), sees base is zero-initialized and event->datalen not yet set in CounterInitMap, and emits a report.
- Later, when event->datalen = datalen executes, checkBind marks the counter initialized, preventing further reports on subsequent writes to event->data.
