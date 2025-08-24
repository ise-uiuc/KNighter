1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarSqMap, const MemRegion*, const MemRegion*)
  - Key: MemRegion of an integer “error” variable that receives the return value of hws_send_ring_set_sq_rdy.
  - Value: MemRegion of the sq object whose sq->sqn was passed to hws_send_ring_set_sq_rdy.
- No other custom traits or alias maps are needed.

2. Chosen callbacks and detailed implementation

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
- Goal: Record when an error variable is assigned the result of hws_send_ring_set_sq_rdy(mdev, sq->sqn).
- Steps:
  1) Ensure S is a BinaryOperator assignment (BO_Assign). Use findSpecificTypeInChildren<BinaryOperator>(S). If not found, return.
  2) Extract LHS expression and obtain its MemRegion via getMemRegionFromExpr(LHS, C). If null, return.
  3) From the RHS, find CallExpr: findSpecificTypeInChildren<CallExpr>(RHS). If absent, return.
  4) Check callee name == "hws_send_ring_set_sq_rdy". If not, return.
  5) Extract the second argument (index 1). Expect a MemberExpr referencing "sqn". Validate either:
     - The argument is a MemberExpr whose member name equals "sqn", and get its base expression (likely DeclRefExpr ‘sq’). Obtain its MemRegion via getMemRegionFromExpr(Base, C). If null, return.
  6) Update state: State = State->set<ErrVarSqMap>(ErrVarRegion, SqRegion) and C.addTransition(State).
- Rationale: This maps the specific “err” variable to the sq object associated with the set-to-ready call.

B) checkBranchCondition(const Stmt *Condition, CheckerContext &C)
- Goal: Detect the misuse pattern in the failure branch immediately guarding the set-to-ready result.
- Common utilities needed:
  - Get the enclosing IfStmt using findSpecificTypeInParents<IfStmt>(Condition, C).
  - A small helper to scan a statement subtree for a call by name: use findSpecificTypeInChildren<CallExpr>(Subtree) and then check the callee name. If needed, scan sequentially by iterating compound children (IfStmt->getThen()) and checking each descendant (keep it simple: call findSpecificTypeInChildren on the whole Then subtree).
  - A helper to extract the sq MemRegion from a call argument:
    - For hws_send_ring_set_sq_rdy: take arg[1] as MemberExpr “sqn”, take its base expr, then getMemRegionFromExpr(base).
    - For hws_send_ring_close_sq: take arg[0] and call getMemRegionFromExpr(arg0).
- Two detection modes:

  Mode 1: Direct-call-in-condition pattern
  - Inspect Condition subtree for a CallExpr to "hws_send_ring_set_sq_rdy".
  - If found:
    - Extract the sq MemRegion from arg[1] (sq->sqn) as described above. If extraction fails, stop.
    - The failure path is the ‘then’ branch if condition is used as-is (e.g., if (hws_send_ring_set_sq_rdy(...))). You can conservatively assume Then is the failure branch for this direct-call pattern.
    - In the Then branch subtree, search for a call to "hws_send_ring_close_sq".
      - If found, get the MemRegion of arg[0] and compare with the sq region from the condition. If equal, this is the bug.
      - Before reporting, optionally check that the Then subtree does not contain a call to "mlx5_core_destroy_sq" or "hws_send_ring_destroy_sq" to avoid flagging a correct cleanup (use another findSpecificTypeInChildren<CallExpr> and compare callee name); if it does, skip reporting.
    - Report: emit a bug at the hws_send_ring_close_sq call site.

  Mode 2: Variable-checked pattern (err variable)
  - Try to obtain a DeclRefExpr within Condition that refers to a variable region present in ErrVarSqMap:
    - Use findSpecificTypeInChildren<DeclRefExpr>(Condition), get MemRegion, and look up in ErrVarSqMap.
    - If found, retrieve the mapped sq MemRegion (SqReg).
  - Decide the failure branch (which side corresponds to a nonzero/failed err):
    - If condition is just “err”, “(err != 0)”, “(err < 0)”, assume Then is failure.
    - If condition is “!err”, or “(err == 0)”, assume Else is failure.
    - Keep this simple by checking for UnaryOperator ‘!’ or BinaryOperator kinds EQ, NE, LT, LE, GT, GE and the constant 0 on the other side. If not sure, default to Then as failure.
  - In the selected failure branch subtree, look for a call to "hws_send_ring_close_sq".
    - If found, get MemRegion of its first arg and compare with SqReg. If equal, this is the bug.
    - Similarly, skip reporting if the same branch subtree also contains "mlx5_core_destroy_sq" or "hws_send_ring_destroy_sq".
  - Report at the close call site.

- Reporting details:
  - Create a non-fatal error node with generateNonFatalErrorNode().
  - Use a concise message, e.g., "Wrong cleanup on failure: hws_send_ring_close_sq may double free; use destroy_sq."

C) checkPreCall(const CallEvent &Call, CheckerContext &C)
- Optional safeguard (not strictly required): If a call to "hws_send_ring_close_sq" is seen, try to find an enclosing IfStmt with a condition matching Mode 1 or Mode 2 logic (by going up via findSpecificTypeInParents to the enclosing IfStmt). If both the condition and the close call match the misuse pattern, report here. This is redundant if checkBranchCondition already flags it; include only if needed to catch cases missed by checkBranchCondition. Prefer keeping it disabled for simplicity.

3. Notes and simplifications
- This checker is intentionally scoped to the mlx5 HWS SQ flow:
  - Creator/readiness function name: "hws_send_ring_set_sq_rdy".
  - Bad cleanup function: "hws_send_ring_close_sq".
  - Correct cleanup: "mlx5_core_destroy_sq" or its wrapper "hws_send_ring_destroy_sq".
- We rely on the common kernel idiom “err = foo(); if (err) …” and the direct-call predicate idiom “if (foo()) …”. We do not attempt complex alias tracking beyond the sq variable extraction and err mapping described.
- We do not need to model values symbolically; the checker is syntactic/structural with light region comparisons only.

4. Utility usage
- findSpecificTypeInParents and findSpecificTypeInChildren:
  - To find the enclosing IfStmt from the condition.
  - To find CallExprs inside the condition or branch bodies.
- getMemRegionFromExpr:
  - To compare that the same sq object is passed to set_sq_rdy (via sq->sqn) and hws_send_ring_close_sq (via sq).
- ExprHasName:
  - Optional for quick checks like ensuring the member name is “sqn” when parsing the arg to set_sq_rdy. Prefer using MemberExpr and checking the FieldDecl’s name via getMemberDecl()->getName() when possible.

5. Bug report
- Use PathSensitiveBugReport with a short message:
  - Title: "Over-broad cleanup in failure path"
  - Message: "hws_send_ring_close_sq may double free; call destroy_sq on failure."
- Anchor the report on the CallExpr to hws_send_ring_close_sq.
