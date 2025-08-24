1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrMap, const MemRegion*, unsigned)
  - We store bit flags per pointer-like region that may come from an “optional” getter:
    - bit0 (1): FromOptionalGetter (the region’s current value originates from an optional getter)
    - bit1 (2): NullCheckedObserved (we have seen a NULL-check on this region on the current path)
    - bit2 (4): ErrCheckedObserved (we have seen an IS_ERR-like check on this region)
  - On reassignments to a tracked region, always overwrite the entry to reflect the newest value source and clear checks accordingly.

- REGISTER_MAP_WITH_PROGRAMSTATE(OptRetSymMap, SymbolRef, char)
  - Temporary map to tag the return symbol of optional getter calls. We use it to transfer the “FromOptionalGetter” flag onto the ultimate destination region when the call’s return is bound.

No other program state traits are necessary for a simple and robust implementation. We will not maintain a general alias graph; instead, we propagate state forward on each bind from source region or from the tagged return symbol.

2) Callbacks and how to implement them

- checkPostCall(const CallEvent &Call, CheckerContext &C) const
  Goal: Mark the return symbol of known optional getters.
  Steps:
  - Identify optional-getter calls:
    - Implement helper isOptionalGetter(const CallEvent&):
      - Return true if the callee name matches any of:
        - "devm_gpiod_get_array_optional"
        - "gpiod_get_array_optional"
        - "devm_gpiod_get_optional"
        - "gpiod_get_optional"
      - Optionally, allow a conservative fallback: if name contains both "get" and "optional", still treat as optional (only if you want broader coverage).
  - If isOptionalGetter(Call):
    - SVal Ret = Call.getReturnValue().
    - If Ret.getAsSymbol() is present, insert into OptRetSymMap with any non-zero dummy value (e.g., 1). This tags the return symbol as “from optional getter”.

- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
  Goal: Transfer the optional-origin property to the destination region and propagate state on assignments.
  Steps:
  - Extract destination region: const MemRegion *Dst = Loc.getAsRegion(); if !Dst, return.
  - Case A: The bound value is the return from an optional getter:
    - If Val has SymbolRef Sym and OptRetSymMap contains Sym:
      - Create/overwrite OptionalPtrMap[Dst] = bit0 (FromOptionalGetter) only; clear bits 1–2.
      - Remove Sym from OptRetSymMap (one-time tag).
      - Add transition.
  - Case B: The bound value aliases another region that is already tracked:
    - If Val.getAsRegion() returns Src and OptionalPtrMap has entry for Src:
      - Copy the flag value from Src to Dst (overwrite any existing Dst entry).
      - Add transition.
  - Case C: Fallback for call-return binding when the return symbol didn’t materialize:
    - If the bound site “S” syntactically contains an optional-getter call:
      - Use findSpecificTypeInChildren<CallExpr>(S) to find the nested call.
      - If found and isOptionalGetter(*CallEvent for that CallExpr), treat as Case A:
        - Set OptionalPtrMap[Dst] = bit0; Add transition.
  - For any other binding that writes a new, non-optional value into a previously tracked destination:
    - If Dst had a prior mapping but this assignment is from a value that is neither tagged symbol nor from tracked Src:
      - Remove Dst from OptionalPtrMap (the pointer no longer refers to an optional resource).
      - Add transition.

- checkBranchCondition(const Stmt *Condition, CheckerContext &C) const
  Goal: Observe checks on tracked pointers: IS_ERR/IS_ERR_OR_NULL and explicit NULL-checks.
  Steps:
  - Identify a tracked region used in the condition:
    - Try to extract a candidate expression that names the pointer:
      - Prefer MemberExpr with pointer access (e.g., “lcd->im_pins”), else DeclRefExpr.
      - Use findSpecificTypeInChildren<MemberExpr>(Condition) and/or DeclRefExpr.
      - For each such expr E, get region R with getMemRegionFromExpr(E, C). Keep the first R that exists in OptionalPtrMap.
    - If no such region found, return.
  - Determine the kind of check:
    - If ExprHasName(cast<Expr>(Condition), "IS_ERR_OR_NULL", C):
      - Set both ErrCheckedObserved (bit2) and NullCheckedObserved (bit1) for R.
      - Add transition.
    - Else if ExprHasName(cast<Expr>(Condition), "IS_ERR", C):
      - Set ErrCheckedObserved (bit2) for R.
      - Add transition.
    - Else, detect common NULL-check shapes for R and set NullCheckedObserved (bit1):
      - BinaryOperator: ptr == NULL or ptr != NULL (either side could be NULL).
      - UnaryOperator: !ptr
      - “Truthiness” check: if (ptr)
        - Heuristic: If Condition contains the pointer expression name and does not contain “IS_ERR” and also does not look like a comparison with non-NULL integer, treat as a NULL-check observation.
      - Implementation detail:
        - You can check the operator kinds by scanning children via findSpecificTypeInChildren<BinaryOperator> / <UnaryOperator>, or fallback to textual heuristics on the Condition with ExprHasName(..., "NULL", C) combined with detecting the region in Condition as above.
  - Note: For simplicity, mark NullCheckedObserved regardless of true/false branch. This is conservative and minimizes false positives in the intended kernel pattern.

- checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const
  Goal: Detect dereferences of tracked optional pointers without a prior NULL-check.
  Steps:
  - Identify dereference base expressions from S:
    - MemberExpr with isArrow() true: base expression is the pointer being dereferenced.
    - UnaryOperator with opcode UO_Deref: operand is the pointer.
    - ArraySubscriptExpr where the base is a pointer (not array): base expression is dereferenced.
    - Use findSpecificTypeInChildren<MemberExpr>(S), then if isArrow(), use ME->getBase().
    - Else use findSpecificTypeInChildren<UnaryOperator>(S) and check for deref op.
    - Else use findSpecificTypeInChildren<ArraySubscriptExpr>(S) and take the base.
  - Resolve the region R for the base expression using getMemRegionFromExpr(E, C).
  - If R is in OptionalPtrMap and FromOptionalGetter (bit0) is set and NullCheckedObserved (bit1) is not set:
    - Report a bug.
      - Create a non-fatal error node with generateNonFatalErrorNode().
      - Emit a PathSensitiveBugReport with a short message, e.g.:
        - "Dereference of optional resource without NULL-check"
      - Optionally, if ErrCheckedObserved (bit2) is set, you can refine the message:
        - "Only IS_ERR() checked; missing NULL-check before dereference"

- Optional: checkEndFunction / checkEndAnalysis
  - No special handling is required; the analyzer will discard per-path state automatically.

3) Additional notes and small helpers

- Function identification:
  - Implement isOptionalGetterName(StringRef N):
    - Return true if N equals any of:
      - "devm_gpiod_get_array_optional"
      - "gpiod_get_array_optional"
      - "devm_gpiod_get_optional"
      - "gpiod_get_optional"
    - Optionally include "IS_ERR_OR_NULL" handling via ExprHasName for condition checks as above.

- Region discovery in conditions:
  - Implement helper getFirstTrackedRegionInCondition(const Stmt *Cond, CheckerContext &C):
    - Try MemberExpr then DeclRefExpr, obtain region via getMemRegionFromExpr().
    - Return the first region that exists in OptionalPtrMap.

- State updates:
  - When writing to a tracked destination region with a new value not coming from the optional getter path, remove it from OptionalPtrMap to avoid stale state.
  - When copying from a tracked source region, copy the entire flag set.

This plan keeps the checker simple and focused:
- It tags values from optional getters.
- It propagates those tags through bindings/assignments.
- It observes IS_ERR and NULL-related conditions.
- It warns when a dereference occurs without a prior NULL-check.
