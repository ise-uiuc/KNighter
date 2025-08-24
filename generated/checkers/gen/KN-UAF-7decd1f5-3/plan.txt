1) Program State

- REGISTER_SET_WITH_PROGRAMSTATE(FreedPtrSyms, SymbolRef)
  - Stores the symbolic values of pointers that have been “released” (i.e., passed to a known release-like function that may free them). Using SymbolRef lets us catch both direct uses and aliases that carry the same pointer value.

- (Optional) REGISTER_SET_WITH_PROGRAMSTATE(ReportedSyms, SymbolRef)
  - To avoid duplicate reports for the same freed symbol along a path. If you prefer simplicity, you can omit this.

2) Helper Data/Functions

- Known release-like functions table:
  - struct KnownReleaseFunction { const char *Name; llvm::SmallVector<unsigned, 4> Params; };
  - Static array with at least:
    - { "mptcp_close_ssk", { 2 } } // 0-based index; third parameter is the subflow that may be freed.
  - You can add more later (e.g., "kfree", "kvfree", etc.), but keep the initial scope narrow to minimize false positives.

- isReleaseLike(const CallEvent &Call, SmallVectorImpl<unsigned> &FreedParams):
  - Look up Call.getCalleeIdentifier()->getName() in the table above.
  - If found, append the param indices that may be freed and return true, else false.

- getArgPointerSymbol(const Expr *Arg, CheckerContext &C) -> SymbolRef:
  - SVal V = C.getState()->getSVal(Arg, C.getLocationContext());
  - Return V.getAsSymbol().
  - If null, return nullptr.

- getBasePointerSymbolFromLoc(SVal Loc) -> SymbolRef:
  - If const MemRegion *R = Loc.getAsRegion(): let Base = R->getBaseRegion().
  - If const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(Base): return SR->getSymbol().
  - Otherwise return nullptr.
  - This recovers the original pointer symbol for loads/stores from subregions like “subflow->request_join”.

3) Callback: checkPostCall

Goal: Mark pointer symbols as freed after calls to mptcp_close_ssk (or other known release functions).

- If not isReleaseLike(Call, FreedParams), return.
- For each index i in FreedParams:
  - const Expr *E = Call.getArgExpr(i); SymbolRef S = getArgPointerSymbol(E, C);
  - If S is non-null:
    - State = C.getState()->add<FreedPtrSyms>(S);
- C.addTransition(State).

Rationale: We model that after the function returns, the object referenced by the given pointer may be freed (or scheduled to be freed), so any dereference of that pointer value is dangerous.

4) Callback: checkLocation

Goal: Detect dereference (read or write) of a pointer symbol that was marked as freed.

- If Loc is not a region, return.
- Extract base pointer symbol: SymbolRef S = getBasePointerSymbolFromLoc(Loc).
- If S is null, return.
- If S is in State->contains<FreedPtrSyms>(S):
  - Optional: If ReportedSyms contains S, return to avoid duplicate spam on the same path; else add S to ReportedSyms.
  - ExplodedNode *N = C.generateNonFatalErrorNode();
  - If !N, return.
  - Static std::unique_ptr<BugType> BT(new BugType(this, "Use-after-free (release-like call)", "Memory Error"));
  - Create a short, clear report:
    - auto R = std::make_unique<PathSensitiveBugReport>(*BT, "Use-after-free: pointer dereferenced after a release-like call (e.g. mptcp_close_ssk)", N);
    - C.emitReport(std::move(R)).

Notes:
- checkLocation is called for both loads and stores; trigger the report for both.
- This catches patterns like “removed |= subflow->request_join;” after mptcp_close_ssk(..., subflow).

5) Callback: checkPreCall (optional but useful)

Goal: Warn if a freed pointer is passed to a function known to dereference it (we have utility functionKnownToDeref).

- Use functionKnownToDeref(Call, DerefParams). If false, return.
- For each index j in DerefParams:
  - SymbolRef S = getArgPointerSymbol(Call.getArgExpr(j), C).
  - If S is non-null and State->contains<FreedPtrSyms>(S):
    - Report similarly to checkLocation with message:
      - "Use-after-free: freed pointer passed to a function that dereferences it".

This catches cases where a freed pointer is used indirectly via a function call that dereferences it.

6) Callback: checkBind (not required)

- No special alias map is required because we track by the SymbolRef of the pointer value. When a pointer variable is rebound to a new value, subsequent dereferences will use a new SymbolRef, so we don’t need to mutate FreedPtrSyms.
- You can omit this for simplicity.

7) Callback: others

- No need for checkBeginFunction/checkEndFunction/checkRegionChanges/etc. Keep the checker minimal.

8) Heuristics/False Positive Control

- Initially only consider mptcp_close_ssk’s third parameter as release-like to minimize false positives and specifically target the reported bug pattern.
- The report is path-sensitive: the freed symbol exists in state only on paths after the call, so dereferences before the call won’t warn.
- If you see duplicate diagnostics on long paths, add ReportedSyms guard as described.

9) How this catches the target bug

- At the call “mptcp_close_ssk(sk, ssk, subflow)”, checkPostCall captures the symbol of “subflow” and marks it freed.
- The subsequent “removed |= subflow->request_join;” triggers checkLocation; it resolves the field access to a FieldRegion whose base is a SymbolicRegion tied to the same “subflow” pointer symbol.
- The checker sees the symbol in FreedPtrSyms and reports “Use-after-free: pointer dereferenced after a release-like call”, matching the UaF fixed by moving the read before the call in the patch.
