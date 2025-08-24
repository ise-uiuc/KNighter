Plan

1) Program state customizations

- REGISTER_SET_WITH_PROGRAMSTATE(ZeroInitObjs, const MemRegion*)
  - Tracks heap objects known to be zero-initialized (returned by kzalloc/kcalloc/kvzalloc/...).

- REGISTER_MAP_WITH_PROGRAMSTATE(CounterInitSet, const MemRegion*, ImmutableSet<const FieldDecl*>)
  - For each tracked base object, stores the set of counter FieldDecls that have been initialized (assigned) along the current path.

No alias map is required: field accesses (p->field) resolve to a FieldRegion whose super region is the underlying base object (heap region), which we use as the map key.

2) Callback functions and steps

A) checkPostCall — record zero-initializing allocations

- Goal: When a zeroing allocator is called, mark its newly created object as zero-initialized.

- Implementation:
  - Add a helper isZeroingAllocator(const CallEvent&): return true if callee name is one of:
    - kzalloc, kcalloc, kvzalloc, __kzalloc, kzalloc_node, devm_kzalloc (small initial set is fine).
  - If true:
    - Obtain the MemRegion of the call expression via getMemRegionFromExpr(Call.getOriginExpr(), C).
      - If this yields a region (loc::MemRegionVal), insert it into ZeroInitObjs.
    - Do not modify CounterInitSet here (it starts empty for this object because counters are zero).

B) checkBind — detect writes to counted_by counter fields

- Goal: Mark a counter field as initialized when the code assigns to it.

- Implementation:
  - Only handle assignment statements:
    - If S is a BinaryOperator with isAssignmentOp(), extract its LHS; else return.
  - If LHS is a MemberExpr referring to a FieldDecl FD:
    - Get the FieldDecl* FD = LHS->getMemberDecl() casted to FieldDecl.
    - Identify the base object region:
      - const MemRegion* FR = dyn_cast<FieldRegion>(getMemRegionFromExpr(LHS, C));
      - If FR is null, return.
      - const MemRegion* Base = FR->getSuperRegion(); strip to the top-most region if necessary (e.g., calling getSuperRegion repeatedly until a non-FieldRegion).
    - Check whether FD is a counted_by counter for any flexible-array member in the same record:
      - Use a helper isCountedByCounterField(const FieldDecl *FD):
        - Let Rec = FD->getParent(); iterate fields of Rec.
        - Find any FieldDecl FAFld that is a flexible array (FAFld->getType()->isIncompleteArrayType()) and that has the counted_by attribute referring to FD:
          - Prefer Clang’s CountedByAttr (FAFld->hasAttr<CountedByAttr>()) and compare the attribute’s referenced field to FD.
          - If the attribute class is not available, skip (we will only rely on the attribute to avoid false positives).
        - Return true if found; otherwise false.
    - If isCountedByCounterField(FD) is true:
      - Load current set S = CounterInitSet.lookup(Base). If empty, create an empty ImmutableSet using the set factory.
      - Add FD into the set (S = SFactory.add(S, FD)).
      - Update state with CounterInitSet = CounterInitSet.set(Base, S).
  - Note: We do not require Base ∈ ZeroInitObjs here; an assignment to a counter is harmless. The ZeroInitObjs gate is applied at use time.

C) checkPreCall — detect writes/reads to flexible-array members before initializing their counters

- Goal: When a copy operation (memcpy/memmove) targets a flexible-array field with __counted_by(counter), ensure the corresponding counter has been initialized on this path if the base object is zero-initialized.

- Implementation:
  - Add a helper isMemCpyLike(const CallEvent&): return true if callee name is one of:
    - memcpy, __memcpy, __builtin_memcpy, memmove, __memmove, __builtin_memmove (keep list small initially).
  - If not isMemCpyLike, return.
  - Extract the destination expression: const Expr* Dst = Call.getArgExpr(0);
    - Try to obtain a FieldRegion from Dst:
      - const MemRegion* MR = getMemRegionFromExpr(Dst, C).
      - If MR is a FieldRegion (or has a FieldRegion after peeling ElementRegion/TypedValueRegion), get FieldDecl* FAFld = that field.
    - Check that:
      - FAFld is a flexible array: FAFld->getType()->isIncompleteArrayType().
      - FAFld has counted_by attribute (FAFld->hasAttr<CountedByAttr>()).
        - If attribute is absent, return (we only want counted_by cases).
    - Obtain the counter FieldDecl* CounterFD from the CountedByAttr bound to FAFld.
    - Resolve the base object region:
      - const MemRegion* Base = FR->getSuperRegion(); strip super regions until the root object.
    - Reduce false positives:
      - If Base ∉ ZeroInitObjs, return (the specific crash pattern is triggered by zero-initialized allocations).
      - Optionally, skip if length arg is provably 0:
        - llvm::APSInt N; if EvaluateExprToInt(N, Call.getArgExpr(2), C) and N == 0, return.
    - Check whether CounterFD is in CounterInitSet for Base:
      - Lookup S = CounterInitSet.lookup(Base). If S is missing or CounterFD ∉ S:
        - Report a bug.
  - Bug report:
    - Use generateNonFatalErrorNode and PathSensitiveBugReport.
    - Short message: "flexible-array accessed before initializing its __counted_by counter".
    - Point to the memcpy call location. Optionally add a note range on the destination expression.

3) Helper functions

- isZeroingAllocator(const CallEvent &Call):
  - Check callee identifier name against: kzalloc, kcalloc, kvzalloc, __kzalloc, kzalloc_node, devm_kzalloc.
  - Return true if matched.

- isMemCpyLike(const CallEvent &Call):
  - Check callee identifier name against: memcpy, __memcpy, __builtin_memcpy, memmove, __memmove, __builtin_memmove.

- getFieldRegionFromExpr(const Expr *E, CheckerContext &C):
  - From getMemRegionFromExpr(E, C), peel ElementRegion/TypedValueRegion to a FieldRegion if present.
  - Return FieldRegion* or nullptr.

- getBaseRegion(const MemRegion *R):
  - Peel FieldRegion/ElementRegion layers via getSuperRegion() until reaching the top object region (e.g., SymbolicRegion/HeapRegion/AllocaRegion).
  - Return that region.

- getCountedByCounterFD(const FieldDecl *FAFld):
  - If FAFld->hasAttr<CountedByAttr>(), return the referenced counter FieldDecl; else return nullptr.

- isCountedByCounterField(const FieldDecl *FD):
  - For FD->getParent() record fields, find any flexible array field (isIncompleteArrayType()) whose CountedByAttr references FD. Return true if found.

- addCounterInit(ProgramStateRef State, const MemRegion *Base, const FieldDecl *FD):
  - Retrieve the ImmutableSet factory from State.
  - Get current set or create empty.
  - Add FD to set and return updated State with CounterInitSet.set(Base, Set).

4) Notes and constraints

- Scope reduction to avoid false positives:
  - Only warn when:
    - Destination is a flexible array field marked with counted_by.
    - The base object is known zero-initialized (in ZeroInitObjs).
    - The length argument is not provably zero.
    - The corresponding counter field has not been assigned beforehand on this path.

- What we intentionally do not handle (to keep it simple):
  - Non-memcpy/memmove accesses (e.g., pointer arithmetic and stores to s->data[i]).
  - Counted-by attribute missing or unrecognized (we skip these).
  - Multiple different counted_by counters in the same struct: handled, since CounterInitSet stores a set of FieldDecl* per object.

- Chosen callbacks summary:
  - checkPostCall: to tag zeroing allocations.
  - checkBind: to mark counter fields as initialized when assigned.
  - checkPreCall: to catch early flexible-array access and emit the bug report.
