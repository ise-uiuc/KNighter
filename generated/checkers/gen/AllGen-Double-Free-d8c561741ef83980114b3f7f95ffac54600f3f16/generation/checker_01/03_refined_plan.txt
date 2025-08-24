Plan

1) Program state customizations
- REGISTER_MAP_WITH_PROGRAMSTATE(CreateRetSymMap, SymbolRef, const MemRegion*)
  - Maps the return symbol of hws_send_ring_create_sq() to the SQ object region (struct mlx5hws_send_ring_sq *) passed to the call. Used to learn on which branch the create succeeded.
- REGISTER_MAP_WITH_PROGRAMSTATE(SetRdyRetSymMap, SymbolRef, const MemRegion*)
  - Maps the return symbol of hws_send_ring_set_sq_rdy() to the SQ object region, derived from the sq->sqn argument. Used to recognize the error branch after the set-to-ready step.
- REGISTER_MAP_WITH_PROGRAMSTATE(SQStateMap, const MemRegion*, unsigned)
  - Tracks a simple state machine for the SQ object region.
  - Values:
    - 1 = Created (mlx5_core_create_sq() step succeeded for this sq)
    - 2 = SetRdyFailedPendingDestroy (set-to-ready failed; we expect the exact destroy/undo, not a full close)

2) Helper classification and extractors
- bool isCreateCall(const CallEvent &Call)
  - Return true if callee name is "hws_send_ring_create_sq".
- bool isSetReadyCall(const CallEvent &Call)
  - Return true if callee name is "hws_send_ring_set_sq_rdy".
- bool isCloseCall(const CallEvent &Call)
  - Return true if callee name is "hws_send_ring_close_sq".
- bool isDestroyCall(const CallEvent &Call)
  - Return true if callee name is "mlx5_core_destroy_sq" or "hws_send_ring_destroy_sq".
- const MemRegion *getSQRegionFromCreate(const CallEvent &Call, CheckerContext &C)
  - For hws_send_ring_create_sq, the 'sq' parameter index is 4 (0-based).
  - Get Call.getArgExpr(4) and use getMemRegionFromExpr() to obtain the base region.
- const MemRegion *getSQRegionFromSetRdy(const CallEvent &Call, CheckerContext &C)
  - For hws_send_ring_set_sq_rdy, the second argument (index 1) is sqn.
  - Obtain Call.getArgExpr(1). Use findSpecificTypeInChildren<MemberExpr>(ArgExpr) to find a MemberExpr. If found and the member name is "sqn", extract its base expression and call getMemRegionFromExpr(BaseExpr) to get the SQ base region. If this fails, return nullptr (do nothing for this call).
- const MemRegion *getSQRegionFromClose(const CallEvent &Call, CheckerContext &C)
  - For hws_send_ring_close_sq, 'sq' is the first parameter (index 0). Use getMemRegionFromExpr().
- const MemRegion *getSQRegionFromDestroy(const CallEvent &Call, CheckerContext &C)
  - For hws_send_ring_destroy_sq, 'sq' is at index 1. Use getMemRegionFromExpr().
  - For mlx5_core_destroy_sq, 'sqn' is at index 1; mirror getSQRegionFromSetRdy: find a MemberExpr named "sqn" and take its base region.

3) Callbacks and detailed logic

- checkPostCall (const CallEvent &Call, CheckerContext &C) const
  - If isCreateCall(Call):
    - Extract SQ region via getSQRegionFromCreate().
    - Get return value symbol: if SymbolRef RetSym = Call.getReturnValue().getAsSymbol() is non-null, record State = State.set<CreateRetSymMap>(RetSym, SQRegion).
  - If isSetReadyCall(Call):
    - Extract SQ region via getSQRegionFromSetRdy().
    - If SymbolRef RetSym is available, record State = State.set<SetRdyRetSymMap>(RetSym, SQRegion).

- evalAssume (ProgramStateRef State, SVal Cond, bool Assumption) const
  - Extract the symbol from Cond (e.g., if Cond is a SymbolVal or wraps one). If no symbol, return State unchanged.
  - If the symbol S is in CreateRetSymMap:
    - Success path is when the condition evaluates to false for “if (err)” patterns, i.e., Assumption == false means err == 0.
    - On Assumption == false:
      - Get the SQ region R from the map.
      - Set SQStateMap[R] = 1 (Created).
    - Remove S from CreateRetSymMap in both branches.
  - If the symbol S is in SetRdyRetSymMap:
    - Error path is when “if (err)” condition evaluates to true, i.e., Assumption == true means err != 0.
    - On Assumption == true:
      - Get SQ region R; update SQStateMap[R] = 2 (SetRdyFailedPendingDestroy). Optionally require that R already has state Created before upgrading, to reduce false positives.
    - Remove S from SetRdyRetSymMap in both branches.

- checkPreCall (const CallEvent &Call, CheckerContext &C) const
  - If isCloseCall(Call):
    - Extract R = getSQRegionFromClose(Call, C). If null, return.
    - Fetch st = SQStateMap[R].
    - If st == 2 (SetRdyFailedPendingDestroy):
      - This is the bug: a full “close” is used on the error path after only create succeeded and set-to-ready failed; we expect a destroy/undo instead.
      - Emit a bug report:
        - Create a non-fatal error node. If null, return.
        - Short message: "Use destroy after set_sq_rdy() failure; close() here may double free."
  - If isDestroyCall(Call):
    - Extract R = getSQRegionFromDestroy(Call, C). If non-null:
      - Clear/erase R from SQStateMap (we are doing the correct undo; no warning here).

- checkEndFunction (const ReturnStmt *RS, CheckerContext &C) const
  - Best-effort cleanup: clear all maps for the current function context (optional; the engine also discards state when leaving the function).

4) Notes on precision and false positives
- The checker is narrowly focused on the specific pair:
  - create: hws_send_ring_create_sq
  - set-to-ready: hws_send_ring_set_sq_rdy
  - expected destroy: mlx5_core_destroy_sq or hws_send_ring_destroy_sq
  - harmful close: hws_send_ring_close_sq
- We only warn when:
  - We are on the error branch of set-to-ready (captured by evalAssume with SetRdyRetSymMap + Assumption == true), and
  - The SQ region is known to be in Created state, and
  - A close() is called with that same SQ region.
- SQ region extraction for set-to-ready/destroy via MemberExpr "sqn" is done using findSpecificTypeInChildren and getMemRegionFromExpr, avoiding complex alias analysis.

5) Utility functions usage
- getMemRegionFromExpr to obtain MemRegion for pointer parameters.
- findSpecificTypeInChildren<MemberExpr> to locate the sq->sqn member use in set-to-ready/destroy calls and retrieve its base region.
- ExprHasName can be used as a fallback assert/check to ensure the member name is "sqn" if useful for robustness.

6) Reporting
- Use a single BugType cached in the checker: "Mismatched cleanup after partial init".
- Report creation:
  - auto N = C.generateNonFatalErrorNode();
  - auto R = std::make_unique<PathSensitiveBugReport>(BugType, "Use destroy after set_sq_rdy() failure; close() here may double free.", N);
  - C.emitReport(std::move(R)).
