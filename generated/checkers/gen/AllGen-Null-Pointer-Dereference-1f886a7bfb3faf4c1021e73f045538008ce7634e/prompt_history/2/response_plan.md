Plan to detect “dereference of devm_kzalloc() result without NULL check”

1) Program State Customization
- REGISTER_SET_WITH_PROGRAMSTATE(DevmMaybeNullSyms, SymbolRef)
  - Tracks return symbols of devm_kzalloc calls that may be NULL.
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrStatusMap, const MemRegion*, bool)
  - Tracks whether a pointer (by MemRegion) has been NULL-checked.
  - false: requires NULL check (unchecked); true: already checked.
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer aliases, e.g., p2 = p1 and p = arr[i].
  - Maps LHS region to the canonical RHS region.

Helper utilities (internal to the checker):
- bool isDevmKzalloc(const CallEvent &Call)
  - Matches callee name exactly to "devm_kzalloc".
- const MemRegion *canonical(const MemRegion *R, ProgramStateRef State)
  - Follows PtrAliasMap (R -> … -> root) until unmapped, returns root.
- void markUnchecked(ProgramStateRef State, const MemRegion *R)
  - Set PtrStatusMap[R] = false (unchecked).
- void markChecked(ProgramStateRef State, const MemRegion *R)
  - Set PtrStatusMap[R] = true (checked).
- bool isCheckedOrAliasedChecked(ProgramStateRef State, const MemRegion *R)
  - Returns true if PtrStatusMap[R] == true OR PtrStatusMap[canonical(R)] == true.
- bool isExplicitlyUnchecked(ProgramStateRef State, const MemRegion *R)
  - Returns true if PtrStatusMap[R] == false OR PtrStatusMap[canonical(R)] == false.

2) Callback Choices and Detailed Steps

A) checkPostCall(const CallEvent &Call, CheckerContext &C)
- Goal: Capture return values of devm_kzalloc as “maybe NULL”.
- Steps:
  - If !isDevmKzalloc(Call), return.
  - Get return SVal: SVal Ret = Call.getReturnValue();
  - If Ret has a SymbolRef (Ret.getAsSymbol()), insert it into DevmMaybeNullSyms.
  - Do not immediately mark any region; propagation to a concrete region happens in checkBind when this symbol is bound to a location.

B) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
- Goal: (1) Mark recipients of devm_kzalloc return as unchecked; (2) Track pointer aliases.
- Steps:
  - Get LHS region from Loc (Loc.castAs<loc::MemRegionVal>().getRegion()).
  - If Val contains a symbol and that symbol is in DevmMaybeNullSyms:
    - Mark LHS region as unchecked: markUnchecked(State, LHSRegion).
    - Optionally erase the symbol from DevmMaybeNullSyms to avoid unbounded growth (not required for correctness).
  - Else, if this is a pointer-to-pointer binding (RHS has a MemRegion):
    - Extract RHS region with Val.getAsRegion().
    - If both LHS and RHS are pointer-typed, record alias:
      - PtrAliasMap[LHSRegion] = canonical(RHSRegion).
    - Do not alter PtrStatusMap here (status propagates via canonical lookup).
  - Special: For bindings to array elements or struct fields (e.g., arr[i] = devm_kzalloc(...)), LHSRegion will be an ElementRegion/FieldRegion; markUnchecked on that region as above.

C) checkBranchCondition(const Stmt *Condition, CheckerContext &C)
- Goal: Mark pointers as “checked” when a NULL check is performed.
- Recognize these patterns and extract the checked expression E:
  - if (ptr) or if (!ptr): handle ImplicitCastExpr of pointer or UnaryOperator (!).
  - if (ptr == NULL) or if (ptr != NULL): BinaryOperator with EQ/NE where one side is a null literal.
- Steps:
  - From Condition AST, locate the pointer expression E being tested.
    - For UnaryOperator(!), use getSubExpr().
    - For BinaryOperator(==/!=), identify the non-null side as E.
    - For a plain pointer-as-condition, E = Condition expr.
  - Get MemRegion* R via getMemRegionFromExpr(E, C).
  - If R is non-null, markChecked(State, R).
    - We do not need to differentiate then/else branches; the existence of a check is sufficient for this checker’s purpose.
  - No need to walk aliases here; deref check will consult both R and canonical(R).

D) checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C)
- Goal: Report dereferences of unchecked devm_kzalloc results through either direct dereference (*) or pointer-to-struct access (->).
- Identify deref base:
  - If S is a MemberExpr with isArrow() == true:
    - Base expression E = MemberExpr->getBase();
  - Else if S is a UnaryOperator with opcode UO_Deref (‘*’):
    - Base expression E = UnaryOperator->getSubExpr();
  - Otherwise, return (not a pointer deref site we care about).
- Steps:
  - Get MemRegion* Rexpr = getMemRegionFromExpr(E, C).
  - If Rexpr is null, return.
  - Compute Rcanon = canonical(Rexpr, State).
  - Decide:
    - If isCheckedOrAliasedChecked(State, Rexpr) => OK, return.
    - Else if isExplicitlyUnchecked(State, Rexpr) => this is a deref of a devm_kzalloc result without a prior NULL check; report a bug.
      - Create a non-fatal error node and emit a PathSensitiveBugReport:
        - Short message: "Dereference of devm_kzalloc() result without NULL check".
      - Optionally markChecked(State, Rexpr) after reporting to avoid duplicate reports on subsequent derefs of the same pointer.

E) Optional: checkPreCall(const CallEvent &Call, CheckerContext &C)
- Not mandatory for this pattern.
- If you also want to catch deref through known-dereferencing APIs, use functionKnownToDeref(Call, Params), then for each dereferenced parameter:
  - Extract the MemRegion for the argument expression.
  - Apply the same logic as in checkLocation (isCheckedOrAliasedChecked / isExplicitlyUnchecked) and report if needed.

3) Key Matching/Extraction Details
- Function matching:
  - isDevmKzalloc uses Call.getCalleeIdentifier()->getName() == "devm_kzalloc".
- Pointer region extraction:
  - Use getMemRegionFromExpr(E, C) consistently to obtain the MemRegion for the pointer variable/expression being tested or dereferenced.
- Alias resolution:
  - canonical(R): follow PtrAliasMap until an unmapped region is found.
  - At deref time, consult both R and canonical(R) in PtrStatusMap:
    - Consider checked if either is true.
    - Consider unchecked if either is false (and at least one entry exists), then warn.

4) Reporting
- BugType: "Possible NULL dereference (devm_kzalloc result)".
- Message: "Dereference of devm_kzalloc() result without NULL check".
- Emit with generateNonFatalErrorNode and PathSensitiveBugReport.
- Point to the dereference expression (S).

5) Notes to match the target patch
- The bug occurs when:
  - arr[i] = devm_kzalloc(...);  // PtrStatusMap[ElementRegion(arr[i])] = false
  - tmp = arr[i];                // PtrAliasMap[tmp] = ElementRegion(arr[i])
  - tmp->field = ...;            // checkLocation sees MemberExpr ‘->’, base tmp:
                                 // consult PtrStatusMap[tmp] or canonical(tmp)=arr[i].
                                 // No prior check on arr[i] or tmp => report.
- If the code performs if (!arr[i]) return -ENOMEM; before deref:
  - checkBranchCondition marks arr[i] as checked; deref is then allowed, and no report is emitted.
