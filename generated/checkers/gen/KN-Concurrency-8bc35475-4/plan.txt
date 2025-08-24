Plan

1) Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(SharedSpecReadMap, const MemRegion*, const Stmt*)
  - Key: the MemRegion of a local variable that receives a suspicious read.
  - Value: the Stmt (read site) where the unconditional read happened. This lets us:
    - Verify source order (read happens before the if).
    - Provide a precise note range when reporting.
- No other traits needed (we avoid pointer aliasing for simplicity; the pattern uses a local temp like “data”).

2) Helper predicates/utilities (small, local helpers)
- isDerefOfWorkDataBits(const Stmt *S, CheckerContext &C) -> const UnaryOperator*
  - Use findSpecificTypeInChildren<UnaryOperator>(S) to find a UO_Deref node.
  - If found, check its sub-expression with ExprHasName(SubExpr, "work_data_bits", C).
  - Return the deref node if it matches; otherwise nullptr.
- getStoreRegion(SVal Loc) -> const MemRegion*
  - Return Loc.getAsRegion().
- conditionHasFromCancel(const Stmt *Cond, CheckerContext &C) -> bool
  - Return ExprHasName(cast<Expr>(Cond), "from_cancel", C).
- getTopLevelLAnd(const Stmt *Cond) -> const BinaryOperator*
  - If Cond->IgnoreImplicit() is a BinaryOperator with opcode BO_LAnd, return it; else nullptr.
- findUsedSharedVarInExpr(const Expr *E, ProgramStateRef State) -> const MemRegion*
  - Use findSpecificTypeInChildren<DeclRefExpr>(E) to get a DeclRefExpr (best-effort; utility returns one).
  - From that DRE, retrieve its region with getMemRegionFromExpr and check if it exists in SharedSpecReadMap.
  - If not found on first try, return nullptr. (Simple and fast; good enough for the target pattern where the single RHS identifier is “data”.)
- isBefore(const Stmt *A, const Stmt *B, CheckerContext &C) -> bool
  - Compare SourceLocations with C.getSourceManager().isBeforeInTranslationUnit(A->getBeginLoc(), B->getBeginLoc()).

3) Callbacks and logic

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
- Goal: mark a local variable when it receives an unconditional dereference of work_data_bits(work).
- Steps:
  1) Get DestR = getStoreRegion(Loc). If null or not a VarRegion, return.
  2) Detect suspicious RHS by pattern match on S:
     - Deref = isDerefOfWorkDataBits(S, C). If null, this bind is not our target; erase DestR from SharedSpecReadMap if present (the variable is overwritten with a non-suspicious value).
     - If Deref is found, add (DestR -> Deref) to SharedSpecReadMap.
        - Rationale: “data = *work_data_bits(work);”
- Notes:
  - This catches both initialization in a DeclStmt and a later assignment, because checkBind observes both.
  - We keep only the most recent mapping per variable. Any subsequent re-assignment will erase or update it.

B) checkBranchCondition(const Stmt *Condition, CheckerContext &C) const
- Goal: detect the if (from_cancel && use(data)) shape where data was read speculatively before the gate.
- Steps:
  1) Quick filter: if not conditionHasFromCancel(Condition, C), return.
  2) Get the top-level LAnd: Bin = getTopLevelLAnd(Condition). If null, return.
  3) Consider RHS = Bin->getRHS()->IgnoreImplicit(). This is where “data” typically appears in the kernel pattern.
  4) Find a used shared var region on RHS: UsedR = findUsedSharedVarInExpr(RHS, State).
     - If UsedR is null, return.
  5) Retrieve the stored read site Stmt* ReadSite = SharedSpecReadMap[UsedR].
     - If absent, return (no prior marked speculative read).
  6) Ensure correct source order: if not isBefore(ReadSite, Condition, C), return. (Avoid flagging cases where the read is inside the gated condition.)
  7) Report:
     - Generate a non-fatal error node; if null, return.
     - Message: "Speculative read of work->data before checking from_cancel"
     - Create a BasicBugReport or PathSensitiveBugReport (short message required).
     - Add the range of ReadSite (the deref) if possible, and highlight RHS of the condition (optional).
     - Emit the report.
- Optional robustness:
  - After reporting, erase UsedR from SharedSpecReadMap to avoid duplicate reports at the same site on other paths.

4) Minimal false-positive controls
- Specific read recognition: only flag when the RHS dereference is exactly of the form "*work_data_bits(...)" via ExprHasName on the deref’s sub-expression. This anchors the checker to the intended kernel idiom.
- Gate recognition: require that the condition text contains "from_cancel".
- Order check: ensure the read happens earlier than the if condition.
- Overwrite clearing: any non-suspicious writes to the same variable erase it from the map.

5) Reporting
- BugType: "Speculative shared read before gate"
- Short message: "Speculative read of work->data before checking from_cancel"
- Explanation (one-liner in description): "Read '*work_data_bits(work)' is done unconditionally; it should be performed only if from_cancel is true to avoid spurious data races."
- Use std::make_unique<BasicBugReport> (or PathSensitiveBugReport if a path note is desirable); use generateNonFatalErrorNode().

6) Summary of used CSA hooks and utilities
- Program state: REGISTER_MAP_WITH_PROGRAMSTATE(SharedSpecReadMap, const MemRegion*, const Stmt*)
- checkBind: mark/clear the local variable when assigned from "*work_data_bits(...)"
- checkBranchCondition: detect if (from_cancel && use(var)) and report
- Utilities used:
  - findSpecificTypeInChildren<UnaryOperator> for deref detection
  - findSpecificTypeInChildren<DeclRefExpr> for RHS var use detection
  - ExprHasName(...) to pinpoint "work_data_bits" and "from_cancel"
  - getMemRegionFromExpr(...) to map DeclRefExpr to MemRegion
  - SourceManager::isBeforeInTranslationUnit(...) for order check

This is the simplest, kernel-focused checker to catch the exact bug pattern addressed by the patch: reading work->data via work_data_bits() speculatively before verifying from_cancel.
