Plan

1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(ReadyErrVarMap, const MemRegion *, unsigned)
  - Maps an integer variable’s region (e.g., “err”) to a resource-pattern index indicating “this variable currently holds the return of a known set_ready()-like call”. The unsigned is the index into our static knowledge base (see Step 2).

2. Knowledge base (hard-coded names for this pattern)
- Define a small static table of resource patterns:
  - Entry 0 (mlx5 sq):
    - ReadySetter: "hws_send_ring_set_sq_rdy"
    - CompositeCloses: {"hws_send_ring_close_sq"}
    - AllowedDestroys: {"mlx5_core_destroy_sq", "hws_send_ring_destroy_sq"}
- Provide helpers:
  - int findReadySetterIndex(StringRef Name): returns the index for a name in ReadySetter, or -1 if not found.
  - bool isCompositeCloseName(unsigned Idx, StringRef Name)
  - bool isAllowedDestroyName(unsigned Idx, StringRef Name)

3. Callbacks to use and how to implement

3.1 checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
- Goal: Track variables assigned from a ReadySetter call.
- Only proceed if S is a BinaryOperator with opcode BO_Assign.
- Extract LHS and RHS expressions:
  - LHS: use getMemRegionFromExpr(LHS, C). If not a VarRegion (or not integral type), ignore.
  - RHS: use findSpecificTypeInChildren<CallExpr>(S) to locate the call on the RHS.
    - If no CallExpr, erase any existing mapping for this LHS VarRegion in ReadyErrVarMap and return.
- From the found CallExpr:
  - Get callee Identifier and its name.
  - If findReadySetterIndex(Name) returns Idx >= 0:
    - State = State->set<ReadyErrVarMap>(LHSRegion, (unsigned)Idx)
  - Else:
    - Remove any prior mapping for this LHSRegion (the error variable no longer corresponds to a set_ready result).
- Rationale: This lets us later recognize conditions like “if (err)” or “if (err != 0)” as guarding an error path right after a specific set_ready() call.

3.2 checkBranchCondition(const Stmt *Condition, CheckerContext &C) const
- Goal: Detect “if (set_ready fails) then composite-close()” pattern.
- Step A: Determine if this condition is about a known ReadySetter failure.
  - Case A1 (inline call in condition):
    - Look for a CallExpr within Condition using findSpecificTypeInChildren<CallExpr>(Condition).
    - If found, get the callee name and look up the ReadySetter index Idx with findReadySetterIndex.
    - If Idx < 0, continue to Case A2; else we consider this a guarded set_ready error path.
  - Case A2 (variable in condition):
    - Collect DeclRefExpr (possibly via walk or just use findSpecificTypeInChildren<DeclRefExpr>(Condition)). If found:
      - Resolve its MemRegion via getMemRegionFromExpr on the DeclRefExpr.
      - Lookup ReadyErrVarMap for this region; if present, retrieve Idx (resource-pattern index). If not present, we do not consider it a guarded set_ready error path.
- If neither A1 nor A2 succeeds, return (this if-condition is not a set_ready error check).
- Step B: Find the containing IfStmt.
  - Use findSpecificTypeInParents<IfStmt>(Condition, C) to get the IfStmt.
  - If null, return.
  - Let Then = IfStmt->getThen().
- Step C: Search Then-body for a call to a composite close
  - Walk the Then subtree to find CallExprs (either write a small recursive visitor or reuse findSpecificTypeInChildren<CallExpr>(Then) once; simplest: check the first CallExpr with findSpecificTypeInChildren and validate callee name; if you implement a trivial loop, stop after you detect the first composite close).
  - For each CallExpr found, get the callee name:
    - If isCompositeCloseName(Idx, Name) is true:
      - (Optional) If Then also contains an AllowedDestroy call (isAllowedDestroyName), you may still report since the composite close is present in the guarded error path.
      - Emit a bug report at this call site (see Reporting in Step 5).
      - Break to avoid duplicate reports for the same IfStmt.
- Step D: Cleanup transient mapping
  - If Case A2 applied (condition variable was mapped in ReadyErrVarMap), consider removing that mapping (State->remove<ReadyErrVarMap>(VarRegion)) to avoid repeated alerts on subsequent unrelated branches.

3.3 Optional: checkPostCall(const CallEvent &Call, CheckerContext &C) const
- Not strictly needed. We handle inline call-in-condition via BranchCondition by searching for a CallExpr child. If desired, you can implement a lightweight detection cache here, but keep it simple as per requirements.

4. Utility details and matching logic
- Getting callee names:
  - From CallExpr: CE->getDirectCallee() and then getIdentifier()->getName() (guard nulls).
- Recognizing condition forms:
  - We don’t evaluate the truth value; we only require the condition to reference either:
    - a direct call to a known ReadySetter; or
    - a variable previously recorded in ReadyErrVarMap.
  - This covers common forms:
    - if (set_ready(...)) { ... }
    - if (err) { ... }
    - if (err != 0) { ... }
    - if (err < 0) { ... }
- Region retrieval:
  - Use getMemRegionFromExpr on LHS of assignment and DeclRefExprs in conditions.
- Child/parent navigation:
  - Use provided findSpecificTypeInChildren and findSpecificTypeInParents for local, simple matching.

5. Reporting
- When a composite close is found in the then-branch of a set_ready error path:
  - Create a non-fatal error node with C.generateNonFatalErrorNode().
  - Emit a PathSensitiveBugReport with a short message:
    - “Composite close in set_ready() error path; call destroy() to avoid double free.”
  - Attach the CallExpr of the composite close as the primary location.
- Category: “Memory Error” or “Resource Management”.
- Do not suggest fix-its; just the short and clear message.

6. Notes and limitations (accepted for simplicity)
- Heuristic, name-based matching using a small knowledge base (hws_send_ring_set_sq_rdy vs hws_send_ring_close_sq).
- Object identity is not enforced (set_ready takes sqn, close takes sq*), which is okay for this targeted checker.
- Only checks direct then-body; if the body uses goto to a label with the close call, this simple plan will not catch it (kept simple by design).
- Only the first found CallExpr in the then-body is checked if you use the provided child-finder; you may implement a trivial recursive walk to check all calls if desired.
