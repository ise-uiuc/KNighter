Plan

1) Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(SQPendingRdyMap, const MemRegion*, const MemRegion*)
  - Key: sq region (struct mlx5hws_send_ring_sq *).
  - Value: mdev region (struct mlx5_core_dev *).
  - Meaning: set_sq_rdy was just invoked for this SQ; on failure the proper rollback is destroy, not close.
- REGISTER_MAP_WITH_PROGRAMSTATE(RetSymToSQMap, SymbolRef, const MemRegion*)
  - Map the symbolic return value of hws_send_ring_set_sq_rdy to the corresponding SQ region.
  - Used to connect “err”-like variables to the specific SQ.
- REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarToSQMap, const MemRegion*, const MemRegion*)
  - Key: region of the variable that stores the return of set_sq_rdy (e.g., ‘err’).
  - Value: the SQ region connected to that return.

2) Targeted functions and how to recognize arguments
- Set-ready function: “hws_send_ring_set_sq_rdy(mdev, sqn)”
  - From CallEvent, check callee name equals "hws_send_ring_set_sq_rdy".
  - Extract mdev region from arg[0] using getMemRegionFromExpr.
  - Extract SQ region from arg[1] by finding a MemberExpr for “sqn” and retrieving its base (the ‘sq’ expression). Use:
    - const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Call.getArgExpr(1));
    - Ensure ME->getMemberDecl()->getNameAsString() == "sqn".
    - Let Base = ME->getBase()->IgnoreImpCasts(); get sq region via getMemRegionFromExpr(Base, C).
- “close” function: “hws_send_ring_close_sq(sq)”
  - Callee name equals "hws_send_ring_close_sq".
  - SQ region is arg[0] via getMemRegionFromExpr.
- “destroy” functions (to avoid false positives/for cleanup if desired):
  - "hws_send_ring_destroy_sq(mdev, sq)" (preferred and present in the fix)
    - SQ region is arg[1].
    - mdev region is arg[0].
  - “mlx5_core_destroy_sq(mdev, sqn)” exists but uses sqn, not sq pointer; we do not rely on it in this checker.

3) Callback selection and implementation details

A) checkPostCall
- Purpose: When we call hws_send_ring_set_sq_rdy, record which SQ is being transitioned, and map its returned error symbol to the SQ.
- Steps:
  1) If callee is "hws_send_ring_set_sq_rdy":
     - Extract mdev region from arg[0].
     - Extract sq region from arg[1] by locating MemberExpr “sqn” and taking its base.
     - Insert SQPendingRdyMap[sqRegion] = mdevRegion.
     - Obtain the symbolic return value: SVal Ret = Call.getReturnValue(); if SymbolRef Sym = Ret.getAsSymbol():
       - Insert RetSymToSQMap[Sym] = sqRegion.

B) checkBind
- Purpose: Connect the “err”-like LHS variable to the SQ for which set_sq_rdy just returned.
- Steps:
  1) If Val is a nonconcrete SVal with SymbolRef Sym, and RetSymToSQMap contains Sym:
     - Let LHSRegion = Loc.getAsRegion(); if null, skip.
     - Let SQRegion = RetSymToSQMap[Sym].
     - Insert ErrVarToSQMap[LHSRegion] = SQRegion.
     - Erase RetSymToSQMap[Sym] (consumed).

C) checkPreCall
- Purpose: Detect the misuse: calling the full close routine in the immediate error path of set_sq_rdy.
- Steps:
  1) If callee is "hws_send_ring_close_sq":
     - Extract sq region from arg[0]; if null, return.
     - Check that SQPendingRdyMap contains sq region; if not present, return (not the mid-initialization case).
     - Find the nearest IfStmt parent of this call: const IfStmt *IfP = findSpecificTypeInParents<IfStmt>(CallExpr or S, C). If null, return (we only warn inside an error branch).
     - From IfP->getCond(), find DeclRefExpr representing the condition variable (the typical ‘err’). Use findSpecificTypeInChildren<DeclRefExpr>(IfP->getCond()) to get a DeclRefExpr; if none, return.
     - Get the MemRegion of that DeclRefExpr via getMemRegionFromExpr; call it CondVarRegion; if null, return.
     - If ErrVarToSQMap[CondVarRegion] == sq region, we are in the error branch tied to the result of set_sq_rdy on this SQ. This is the buggy pattern.
       - Report a bug:
         - Message: "Use destroy for partially initialized SQ; 'close' here may double free."
         - Create error node: auto N = C.generateNonFatalErrorNode(); then emit std::make_unique<PathSensitiveBugReport>(...).
       - Optionally, remove SQPendingRdyMap[sq] to avoid duplicate warnings along this path.
  2) If callee is "hws_send_ring_destroy_sq":
     - It’s the correct cleanup. Optionally clear SQPendingRdyMap for arg[1] SQ region to keep state tidy.

D) checkBranchCondition (optional refinement, keep simple)
- Not strictly required if we detect the IfStmt parent in checkPreCall. We can omit this to keep the checker simple.

E) checkEndFunction
- Clean up all program state maps (CSA will discard with the context; no explicit action required).

4) Heuristics to reduce false positives
- Only warn if:
  - A corresponding hws_send_ring_set_sq_rdy happened (SQPendingRdyMap contains the SQ region).
  - The close call is inside an IfStmt branch whose condition variable is mapped in ErrVarToSQMap to the same SQ (ensures it’s an immediate error path for that specific call).
- Do not warn on destroy calls.
- Do not attempt to match mlx5_core_destroy_sq since it takes sqn; the checker’s goal is to catch the “close in error path” misuse.

5) Utility usage
- findSpecificTypeInChildren<MemberExpr> and MemberDecl::getNameAsString() to detect the “sqn” access and recover the base ‘sq’.
- getMemRegionFromExpr to convert expressions (mdev, sq, error variable) to MemRegion keys.
- findSpecificTypeInParents<IfStmt> to locate the enclosing if of the cleanup call.
- ExprHasName is not necessary if you extract DeclRefExpr and MemRegions directly.

6) Reporting
- Use a concise message:
  - Title: "Wrong cleanup in error path"
  - Description: "Use destroy for partially initialized SQ; 'close' here may double free."
- Emit via PathSensitiveBugReport with generateNonFatalErrorNode.
