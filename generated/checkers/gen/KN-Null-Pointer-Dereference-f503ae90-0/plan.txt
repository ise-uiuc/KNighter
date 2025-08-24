1) Program state customization

- Register a set of symbols that may be NULL and are not checked yet:
  - REGISTER_SET_WITH_PROGRAMSTATE(UncheckedCapPtrSyms, SymbolRef)
  - Rationale: Track the symbolic value returned by mt76_connac_get_he_phy_cap. Using SymbolRef avoids alias tracking complexity since the same symbol flows through assignments, casts, etc.


2) Helper utilities (internal to the checker)

- isCapHelper(const CallEvent &Call):
  - Return true if callee name equals "mt76_connac_get_he_phy_cap".
- tryGetBaseSymbolFromRegionChain(const MemRegion *R, bool &WentThroughSubRegion):
  - Walk up the region chain:
    - If R is ElementRegion, FieldRegion, or any SubRegion, set WentThroughSubRegion=true and continue with its super region.
    - If R is SymbolicRegion, return SR->getSymbol().
    - Otherwise, return nullptr.
  - This identifies the base symbol that the access is derived from, and whether accessing this region required dereferencing a pointer (WentThroughSubRegion).
- isDefinitelyNonNull(SymbolRef Sym, ProgramStateRef State, CheckerContext &C):
  - Construct loc::SymbolVal Ptr = C.getSValBuilder().makeLoc(Sym) (or loc::SymbolVal(Sym) if available).
  - Build DefinedOrUnknownSVal IsNull = SValBuilder.evalEQ(State, Ptr, SValBuilder.makeNull()).
  - If State->assume(IsNull, false) != nullptr and State->assume(IsNull, true) == nullptr, it’s definitely non-NULL.
  - Return true in that case; otherwise false.
- shouldReport(SymbolRef Sym, bool WentThroughSubRegion, ProgramStateRef State, CheckerContext &C):
  - Return true only if:
    - Sym is in UncheckedCapPtrSyms,
    - WentThroughSubRegion == true (meaning we are dereferencing the pointer, e.g., via ->, [] or computing address of a field),
    - and not isDefinitelyNonNull(Sym, State, C).
  - This ensures we report only when dereference actually happens and the path does not already guarantee non-NULL.


3) Callback: checkPostCall

- Goal: Mark the return value of mt76_connac_get_he_phy_cap as possibly NULL and unchecked.
- Steps:
  - If !isCapHelper(Call): return.
  - Get the return SVal: SVal Ret = Call.getReturnValue().
  - If SymbolRef Sym = Ret.getAsSymbol() is non-null:
    - State = C.getState()->add<UncheckedCapPtrSyms>(Sym).
    - C.addTransition(State).
- Notes:
  - No need to bind a region or model allocation; just track the symbol.


4) Callback: checkBind

- Goal: Detect dereference via lvalue formation and address-taking, e.g., ve = &vc->he_cap_elem; This does not necessarily perform a memory load but still dereferences vc.
- Steps:
  - If Val is not a loc::MemRegionVal, return.
  - const MemRegion *R = Val.getAsRegion().
  - bool Through = false; SymbolRef BaseSym = tryGetBaseSymbolFromRegionChain(R, Through).
  - If BaseSym && shouldReport(BaseSym, Through, C.getState(), C):
    - Generate a non-fatal error node and emit a report.
- Reporting:
  - Create a single BugType (class member) like: BugType BT(this, "NULL dereference of capability pointer", "API Misuse").
  - Use std::make_unique<PathSensitiveBugReport>(BT, "Dereference of pointer returned by mt76_connac_get_he_phy_cap without NULL check", Node).
  - Attach the source range of S (the Stmt argument given) if available.


5) Callback: checkLocation

- Goal: Detect dereference at actual memory loads/stores (e.g., vc->field reads, vc[i], *vc).
- Steps:
  - If Loc is not loc::MemRegionVal, return.
  - const MemRegion *R = Loc.getAsRegion().
  - bool Through = false; SymbolRef BaseSym = tryGetBaseSymbolFromRegionChain(R, Through).
  - If BaseSym && shouldReport(BaseSym, Through, C.getState(), C):
    - Generate a non-fatal error node and emit a report with the same bug type and message as in checkBind.
- Notes:
  - This complements checkBind to cover both forming lvalues and actual loads/stores.


6) No need for alias tracking or explicit branch modeling

- We do not use check::BranchCondition or evalAssume.
- Reason: We rely on the analyzer’s own path constraints when evaluating isDefinitelyNonNull at the point of dereference. If the pointer was checked via if (vc) or similar before dereferencing, the constraint manager will make State->assume(IsNull, true) infeasible and we won’t report.
- This keeps the checker simple and avoids manual state splitting and alias maps.


7) Scope and function matching

- The checker only tracks pointers returned by mt76_connac_get_he_phy_cap (the buggy pattern in the patch). If you want to generalize, extend isCapHelper to include other capability-retrieval helpers known to return NULL when unsupported.


8) Summary of minimal implementation steps

- Program state: REGISTER_SET_WITH_PROGRAMSTATE(UncheckedCapPtrSyms, SymbolRef).
- checkPostCall: Track return symbol of mt76_connac_get_he_phy_cap by inserting into UncheckedCapPtrSyms.
- checkBind: If binding a Loc that forms an lvalue derived from a SymbolicRegion whose symbol is in UncheckedCapPtrSyms and not provably non-NULL, report.
- checkLocation: Same detection logic as checkBind for loads/stores.
- Reporting: Short message: "Dereference of pointer returned by mt76_connac_get_he_phy_cap without NULL check".
