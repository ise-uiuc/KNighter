Plan

1) Program state

- REGISTER_SET_WITH_PROGRAMSTATE(FreedSymSet, SymbolRef)
  - Tracks symbols of objects that may have been released/freed.
  - We deliberately key by the “pointee” symbol (the symbolic base of the region pointed to), so aliases of the same object share the same symbol.

- Optional small helper (no state):
  - A helper to extract the pointee’s SymbolRef from an SVal (see steps below).

2) Known-free function table

- Add a small table and helper similar to functionKnownToDeref:
  - struct KnownFreeFunction { const char *Name; SmallVector<unsigned,4> Params; };
  - bool functionKnownToFree(const CallEvent &Call, SmallVectorImpl<unsigned> &FreeParams)
    - If callee name matches a known entry, return true and fill the params that may free their object.
  - Populate with at least:
    - "mptcp_close_ssk" with Params {2}  // third argument: subflow
    - Optionally add "kfree", "kvfree", "kfree_rcu" with {0} if you want broader coverage.

3) Common helper: extract pointee symbol

- SymbolRef getPointeeSymbolFromSVal(SVal V)
  - If V.isUnknownOrUndef(), return nullptr.
  - If V is loc::MemRegionVal and has a region R: return R->getSymbolicBase()->getSymbol() if available.
  - If V is a SymbolVal: return V.getAsSymbol().
  - If V is a loc::ConcreteInt (NULL), return nullptr.
  - Otherwise return nullptr.

- SymbolRef getBaseObjectSymbolFromRegion(const MemRegion *R)
  - If R is null, return nullptr.
  - Use R->getSymbolicBase(); if it’s a SymbolicRegion, return its symbol.
  - This is used to detect dereferences of possibly-freed objects via field/element regions.

4) checkPostCall: mark objects as possibly freed

- Purpose: After calling a function that can release memory/refs for certain arguments (e.g., mptcp_close_ssk(..., subflow)), mark the pointed-to object as possibly freed.
- Steps:
  - Resolve if the call is in our “known-free” table via functionKnownToFree(Call, FreeParams).
  - For each index i in FreeParams:
    - SVal ArgV = Call.getArgSVal(i).
    - SymbolRef PointeeSym = getPointeeSymbolFromSVal(ArgV).
    - If PointeeSym, add it to FreedSymSet: State = State->add<FreedSymSet>(PointeeSym).
  - Bind the updated state in the context.

5) checkLocation: detect dereference of a possibly-freed object

- Purpose: Catch use-after-free when code accesses fields or memory derived from a freed object (e.g., subflow->request_join after mptcp_close_ssk(..., subflow)).
- Triggered on loads and stores.
- Steps:
  - If Loc is not a loc::MemRegionVal, bail out.
  - const MemRegion *R = Loc.getAsRegion().
  - SymbolRef BaseSym = getBaseObjectSymbolFromRegion(R).
  - If BaseSym is null, bail.
  - If State->contains<FreedSymSet>(BaseSym):
    - Generate a non-fatal error node.
    - Emit a PathSensitiveBugReport with a short message such as:
      - "Use-after-free: object accessed after a call that may free it"
    - Highlight the statement S as the location. Stop on first report for this node.

6) checkPreCall: detect passing a freed object to a function that dereferences it

- Purpose: In addition to direct field/indirection access, catch UAF when a freed pointer is passed into a function known to dereference that pointer parameter.
- Steps:
  - Query functionKnownToDeref(Call, DerefParams) using the provided utility.
  - For each idx in DerefParams:
    - SVal ArgV = Call.getArgSVal(idx).
    - SymbolRef PointeeSym = getPointeeSymbolFromSVal(ArgV).
    - If PointeeSym and State->contains<FreedSymSet>(PointeeSym):
      - Generate a non-fatal error node.
      - Emit a PathSensitiveBugReport with a short message:
        - "Use-after-free: passing freed object to a function that dereferences it"

7) Why this catches the target bug

- The call mptcp_close_ssk(sk, ssk, subflow) adds the symbol for subflow’s pointee into FreedSymSet in checkPostCall.
- The subsequent access subflow->request_join triggers checkLocation. The lvalue location is a FieldRegion; its base symbolic region corresponds to the same symbol added to FreedSymSet. The checker reports a UAF read.
- Moving the read before mptcp_close_ssk (as in the patch) avoids the warning.

8) Minimality and robustness notes

- No alias map is needed: we track the pointee symbol, which is preserved across simple aliases.
- No need to inspect specific AST parents/children explicitly; checkLocation and call hooks cover both field dereferences and call-argument dereferences.
- The approach is path-sensitive and reports only on the path where the free-like call happens before the access.
- If desired, extend the known-free table later to widen coverage with minimal code changes.

9) Reporting

- Use a single BugType retained by the checker (e.g., "Use-after-free after close/release").
- Create reports via generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>.
- Keep message short and clear:
  - For field/indirection access: "Use-after-free: object accessed after a call that may free it"
  - For deref-in-call: "Use-after-free: passing freed object to a function that dereferences it"
