Plan

1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(SQCreated, const MemRegion*, bool)
  - Tracks “software SQ object” instances (the base pointer/struct region for sq) that have had a successful low-level create call observed.

- REGISTER_MAP_WITH_PROGRAMSTATE(SQFieldToBase, const MemRegion*, const MemRegion*)
  - Maps the field region of sq->sqn to the base MemRegion of sq. This lets us correlate calls that pass sq->sqn (by address or by value) with the owning sq object.

- REGISTER_MAP_WITH_PROGRAMSTATE(RetSymToSQBase, SymbolRef, const MemRegion*)
  - Maps the symbolic return value from hws_send_ring_set_sq_rdy() to the owning sq base region. This is used to recognize the error branch when the condition checks that return.

- REGISTER_MAP_WITH_PROGRAMSTATE(SQErrBranchActive, const MemRegion*, bool)
  - Marks that we are currently in the error branch that corresponds to “set_sq_rdy() failed” for a specific sq. This is path-sensitive and only present on the branch where the condition is true.


2) Helper identification and extraction

- Function recognition by name:
  - isCreateSQ(Call): callee == "mlx5_core_create_sq"
  - isSetSQReady(Call): callee == "hws_send_ring_set_sq_rdy"
  - isCloseSQ(Call): callee == "hws_send_ring_close_sq"
  - isDestroySQ(Call): callee == "mlx5_core_destroy_sq"

- Extract base sq region from expressions:
  - From &sq->sqn:
    - Use findSpecificTypeInChildren<MemberExpr>(ArgExpr) to get the MemberExpr (ME).
    - Base expression: ME->getBase()->IgnoreImpCasts().
    - Base region: getMemRegionFromExpr(BaseExpr, C).
    - Field region: getMemRegionFromExpr(ME, C) (the region of sq->sqn).
  - From sq->sqn (by value):
    - Same MemberExpr extraction and base-region derivation as above.

- If extraction fails (not a MemberExpr on sq->sqn), skip to avoid false positives. Keep the logic simple and conservative.


3) checkPostCall

- For mlx5_core_create_sq:
  - Obtain the 4th argument (index 3) expression; expect it to be &sq->sqn.
  - Extract FieldRegion (sq->sqn) and BaseRegion (sq) as described above.
  - Record SQFieldToBase[FieldRegion] = BaseRegion.
  - Mark SQCreated[BaseRegion] = true.

- For hws_send_ring_set_sq_rdy:
  - Obtain the 2nd argument (index 1) expression; expect sq->sqn by value.
  - Extract FieldRegion from the MemberExpr; look up BaseRegion via SQFieldToBase[FieldRegion].
  - Get the return SVal of the call; if it has a SymbolRef RetSym:
    - RetSymToSQBase[RetSym] = BaseRegion.
    - Optionally clear any stale SQErrBranchActive[BaseRegion] entry to ensure we only react to the most recent call (not strictly necessary, but keeps state clean).


4) checkBranchCondition

- Purpose: detect the “error branch” that checks the return from hws_send_ring_set_sq_rdy.
- If Condition is an Expr:
  - SVal CondV = Ctx.getSVal(Expr).
  - If CondV is a DefinedOrUnknownSVal backed by a SymbolRef Sym (e.g., “if (err)” pattern):
    - Query RetSymToSQBase[Sym] to get BaseRegion.
    - If found, split states using assume:
      - auto [StateT, StateF] = Ctx.getState()->assume(CondV);
      - If StateT: set SQErrBranchActive[BaseRegion] = true in StateT.
      - If StateF: remove SQErrBranchActive[BaseRegion] (or set false) in StateF.
      - Emit transitions for the available states and return.
- If no matching symbol/base found, do nothing (let the core handle branching).


5) checkPreCall

- For hws_send_ring_close_sq:
  - Extract the argument (index 0) as the BaseRegion (sq).
  - Check:
    - SQCreated[BaseRegion] == true (we observed a prior create)
    - SQErrBranchActive[BaseRegion] == true (we are in “set_sq_rdy failed” branch)
  - If both hold, report a bug:
    - Create a non-fatal error node and emit a PathSensitiveBugReport.
    - Message: “High-level close in error path after set_sq_rdy; may double free. Use mlx5_core_destroy_sq().”
  - Regardless of reporting, do not mutate state here (let path sensitivity handle flow). The presence of SQErrBranchActive is already branch-specific.

- For mlx5_core_destroy_sq (optional cleanup):
  - If you want to minimize follow-up noise, extract BaseRegion from context if available (not strictly necessary).
  - If the function uses only sqn, you can skip updating SQCreated; the main goal is to flag the wrong close in the error branch.


6) Notes and simplifications

- We purposely require:
  - Observed create_sq with &sq->sqn before warning (SQCreated flag).
  - Error branch detected specifically from the return value of set_sq_rdy (via RetSymToSQBase and BranchCondition).
  - The close call must pass the same sq object we mapped (argument 0).
- This keeps the checker precise for the target pattern and avoids generic double-free heuristics.
- We do not attempt to track aliasing of sq or sqn beyond straightforward MemberExpr extraction (simple and robust for this case).


7) Bug report details

- Use generateNonFatalErrorNode for the error node.
- Use std::make_unique<PathSensitiveBugReport> with a short message:
  - Title: “Wrong cleanup after SQ set_rdy failure”
  - Description: “High-level close in intermediate error path may double free; call mlx5_core_destroy_sq().”
- Attach the call to hws_send_ring_close_sq as the interesting location.
