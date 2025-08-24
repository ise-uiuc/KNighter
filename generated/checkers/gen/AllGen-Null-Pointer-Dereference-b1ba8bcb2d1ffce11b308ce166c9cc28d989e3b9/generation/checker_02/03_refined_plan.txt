1) Program state customizations
- REGISTER_SET_WITH_PROGRAMSTATE(OptionalRetSyms, SymbolRef)
  - Set of return symbols from calls that can legitimately return NULL (i.e., “_optional” getters).
- REGISTER_MAP_WITH_PROGRAMSTATE(OptionalRetSymOrigin, SymbolRef, const Stmt*)
  - For diagnostics: remembers the call site that produced the optional return symbol.
- REGISTER_MAP_WITH_PROGRAMSTATE(OptionalRegionChecked, const MemRegion*, bool)
  - Tracks “optional pointer” regions and whether they have been NULL-checked (true = checked, false = unchecked).
- REGISTER_MAP_WITH_PROGRAMSTATE(OptionalRegionOrigin, const MemRegion*, const Stmt*)
  - For diagnostics: remembers the call stmt that originated the optional region.

Rationale:
- We first tag the return symbol of an optional getter, then on assignment/binding we transfer that tag to the destination region and mark it as unchecked. Later, when we see a NULL-check we mark the region as checked. On dereference, we report only if the region is tracked as unchecked.

2) Callback functions, responsibilities, and implementation details

A) checkPostCall
- Goal: Identify calls to optional getters and tag their return symbol.
- Detect callee by name. Maintain a small allowlist of functions that can return NULL on absence (not error):
  - "devm_gpiod_get_optional"
  - "devm_gpiod_get_array_optional"
  - "gpiod_get_optional"
  - You can extend with other well-known *_get_optional() as needed later, but keep it small to avoid false positives.
- Steps:
  1. If callee matches one of the above names:
     - Get SVal Ret = Call.getReturnValue(); SymbolRef Sym = Ret.getAsSymbol();
     - If Sym:
       - State = State.add(OptionalRetSyms, Sym);
       - State = State.set(OptionalRetSymOrigin, Sym, Call.getOriginExpr() or Call.getSourceRange/Stmt as available).
     - addTransition(State).

B) checkBind
- Goal: Transfer “optional possibly-NULL” tag from return symbol to the region being assigned to. Also propagate between regions on plain assignments.
- Steps:
  1. Extract the destination region: if Loc is a loc::MemRegionVal, const MemRegion *DstR = Loc.getAsRegion().
  2. Analyze source (Val):
     - If Val has a SymbolRef RHSym and RHSym ∈ OptionalRetSyms:
       - State = State.set(OptionalRegionChecked, DstR, false);
       - Copy origin: const Stmt* CallS = State.get(OptionalRetSymOrigin, RHSym); if (CallS) State = State.set(OptionalRegionOrigin, DstR, CallS);
     - Else if Val refers to a region (e.g., Val.getAsRegion() or cast via loc::MemRegionVal) and that SrcR ∈ OptionalRegionChecked:
       - bool Checked = State.get(OptionalRegionChecked, SrcR);
       - State = State.set(OptionalRegionChecked, DstR, Checked);
       - Also propagate origin: CallS = State.get(OptionalRegionOrigin, SrcR); if (CallS) State = State.set(OptionalRegionOrigin, DstR, CallS);
  3. addTransition(State).
- Notes:
  - This gives minimal alias tracking sufficient for common patterns: storing the optional return into a variable/field and then using that variable/field, or copying it to another pointer.

C) checkBranchCondition
- Goal: Mark regions as checked when they undergo a NULL-check.
- Patterns to recognize:
  - if (ptr)
  - if (ptr != NULL)
  - if (NULL != ptr)
  - if (!!ptr) (via ignoring implicit casts and unary nots)
- Steps:
  1. From Condition (Stmt*), try to extract the pointer expression being tested:
     - If UnaryOperator is ‘!’ or has implicit casts, strip them to reach the underlying Expr.
     - For BinaryOperator ‘==’/‘!=’, identify which side is the pointer and which side is NULL/0:
       - Recognize integer literal 0, GNU __null, or identifier “NULL” via ExprHasName(..., "NULL", C) fallback if needed.
     - For simple “if (ptr)”, the condition is just the pointer with implicit cast to bool; strip casts using IgnoreParenImpCasts().
  2. Get its region: const MemRegion* R = getMemRegionFromExpr(TestExpr, C).
  3. If R is in OptionalRegionChecked:
     - State = State.set(OptionalRegionChecked, R, true);
     - addTransition(State).
- Simplicity note:
  - This approach marks the region as checked regardless of then/else path. It is a pragmatic approximation that works well for the “if (ptr) { … deref … }” kernel pattern. It intentionally does not treat “if (!ptr) { return; } … deref …” path-sensitively to keep the checker simple.

D) checkLocation
- Goal: Detect unchecked dereferences of optional pointers.
- We only warn on actual dereference, not when the pointer is only being compared or passed around.
- Steps:
  1. Trigger only for IsLoad == true.
  2. Extract the region being loaded from: if Loc is a MemRegionVal, const MemRegion* R = Loc.getAsRegion().
  3. If R is not in OptionalRegionChecked map, return (not tracked).
  4. If R is tracked and its value is false (unchecked), determine if this load corresponds to a dereference context:
     - Use the provided utility findSpecificTypeInParents to look for:
       - MemberExpr ME with ME->isArrow() == true (ptr->field)
       - ArraySubscriptExpr (ptr[i])
       - UnaryOperator with opcode UO_Deref (*ptr)
     - If none of the above ancestors exist, ignore (e.g., it could be a benign load for comparison).
  5. If dereference context found:
     - Generate a non-fatal error node and emit a bug report:
       - Message: "Optional resource may be NULL; dereferenced without NULL check"
       - If available, add a note pointing to the origin call site: retrieve OptionalRegionOrigin[R] and add a note like "Optional getter can return NULL here".
     - Optionally, to reduce duplicate reports, you can remove R from the map after reporting on this node/state.

E) Optional: checkEndFunction
- Clear state (not strictly necessary; state is per-function) or leave as is.

3) Additional details and heuristics

- Function identification:
  - Implement a small helper: bool isOptionalGetter(const CallEvent &Call) that returns true if callee name equals one of:
    - "devm_gpiod_get_optional"
    - "devm_gpiod_get_array_optional"
    - "gpiod_get_optional"
  - Keep the list tight to avoid false positives.
- Avoid suppressing for IS_ERR() checks:
  - Do not mark as checked when code checks IS_ERR(ptr). That check validates “error pointer” ranges, not NULL. The checker should still warn if later dereferenced without an explicit null-check.
- Origin tracking:
  - The OptionalRetSymOrigin and OptionalRegionOrigin maps are solely for better diagnostics; if unavailable, the core detection still works.
- Utility usage:
  - Use getMemRegionFromExpr to map expressions to regions.
  - Use findSpecificTypeInParents in checkLocation to confirm dereference contexts.
  - Use ExprHasName to help detect comparisons to NULL in ambiguous cases (though comparing to integer literal 0 is the main case).
- Reporting style:
  - Create a BugType once (e.g., "Unchecked dereference of optional resource").
  - Use std::make_unique<PathSensitiveBugReport> with a short message.

4) Minimal end-to-end flow (as in the target patch)
- devm_gpiod_get_array_optional(...) is called:
  - checkPostCall marks return symbol as optional.
- Assignment to lcd->im_pins:
  - checkBind transfers the tag to the field region and sets it Unchecked.
- Code checks IS_ERR(lcd->im_pins) only:
  - No NULL check detected, so region remains Unchecked.
- Later deref lcd->im_pins->ndescs or lcd->im_pins->desc[i]:
  - checkLocation sees a load from the field region, detects it occurs under a MemberExpr with “->”, and since region is Unchecked, it reports the bug.

This plan directly captures the bug pattern in the provided patch: using an optional getter, failing to test for NULL, and then dereferencing the pointer.
