1) Program State

- REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedMap, const MemRegion*, bool)
  - Tracks pointer variables (as MemRegion) that have been “possibly freed” by a known release/close/free call. Value true means released.

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks simple pointer aliasing: Dest -> Canonical source MemRegion.

Helpers:
- const MemRegion* canon(const MemRegion *R, ProgramStateRef State)
  - Follow PtrAliasMap chain until fixed point to get a canonical region for lookups/updates in ReleasedMap.
- bool functionMayFreeParam(const CallEvent &Call, llvm::SmallVectorImpl<unsigned> &FreeParams)
  - A small hardcoded table of functions that can free certain parameter indices. Include at least:
    - mptcp_close_ssk: frees param index 2 (third argument).
    - kfree, kvfree: free param index 0 (first argument). Optional but useful generally.
- Use provided getMemRegionFromExpr(E, C) to obtain MemRegion from an argument/base expression.
- Optionally keep a second map with blame site if desired:
  - REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedByMap, const MemRegion*, const Stmt*) to store the Stmt of the releasing call for better diagnostics (optional; keep simple if not needed).

2) Callbacks and Implementation Steps

A) checkPostCall (mark regions as “possibly freed”)
- If functionMayFreeParam(Call, FreeParams) is true:
  - For each index in FreeParams:
    - Get the argument expression Arg = Call.getArgExpr(idx).
    - R = getMemRegionFromExpr(Arg, C). If null, skip.
    - Rcanon = canon(R, State).
    - State = State->set<ReleasedMap>(Rcanon, true).
    - If using ReleasedByMap, also set ReleasedByMap[Rcanon] = Call.getOriginExpr() or Call.getStmt().

Rationale: After the call returns, the passed object may be freed or scheduled to be freed (RCU); subsequent dereferences are suspicious.

B) checkBind (track pointer aliases and reset when overwritten)
- If Loc corresponds to binding a value into a region DestR (i.e., DestR = Loc.getAsRegion(), DestR is a VarRegion or a TypedValueRegion of pointer type):
  - If Val has a source region SrcR (e.g., Val.getAsRegion()):
    - SrcCanon = canon(SrcR, State).
    - State = State->set<PtrAliasMap>(DestR, SrcCanon).
  - Else (Val is not a region, e.g., a new allocation, integer, null, unknown):
    - Remove DestR from PtrAliasMap (State = State->remove<PtrAliasMap>(DestR)).
    - Also remove possible ReleasedMap for DestR (State = State->remove<ReleasedMap>(canon(DestR, State))).
      - This avoids propagating a stale “released” tag if the pointer variable is overwritten with a fresh, non-aliased value.

Notes:
- Keep alias tracking simple and one-directional (Dest -> CanonicalSource).
- canon() should be used everywhere to compare against ReleasedMap.

C) checkPreCall (detect deref-through-call on released pointers)
- Use provided functionKnownToDeref(Call, DerefParams).
- For each idx in DerefParams:
  - ArgR = getMemRegionFromExpr(Call.getArgExpr(idx), C).
  - If ArgR:
    - Rcanon = canon(ArgR, State).
    - If ReleasedMap contains Rcanon as true:
      - Report bug: Use-after-free: passing a freed pointer to a function that dereferences it.
      - Use generateNonFatalErrorNode and emit a PathSensitiveBugReport with a short message.
      - Optionally add a note pointing to the releasing call using ReleasedByMap.

D) checkLocation (detect field or pointer dereferences in expressions)
- On every load (IsLoad == true):
  - Try to recognize dereference patterns via AST context around S:
    - MemberExpr with “->”: use findSpecificTypeInParents<MemberExpr>(S, C).
      - If found ME and ME->isArrow():
        - Base = ME->getBase()->IgnoreParenImpCasts();
        - BaseR = getMemRegionFromExpr(Base, C).
        - If BaseR:
          - Rcanon = canon(BaseR, State).
          - If ReleasedMap[Rcanon] == true:
            - Report bug: Use-after-free: field read of a freed object.
    - UnaryOperator with UO_Deref (“*ptr”): use findSpecificTypeInParents<UnaryOperator>(S, C).
      - If found and UO.getOpcode() == UO_Deref:
        - PtrE = UO.getSubExpr()->IgnoreParenImpCasts();
        - PtrR = getMemRegionFromExpr(PtrE, C).
        - Check ReleasedMap[canon(PtrR)] similarly and report.
    - Optionally ArraySubscriptExpr (“ptr[i]”): findSpecificTypeInParents<ArraySubscriptExpr>(S, C).
      - BaseE = ASE->getBase()->IgnoreParenImpCasts();
      - BaseR = getMemRegionFromExpr(BaseE, C).
      - Check ReleasedMap[canon(BaseR)] similarly and report.

Notes:
- These three patterns cover most dereference cases in C code, including the target pattern subflow->request_join.

E) Optional: checkEndFunction
- No special handling needed; program-state is path-local.

3) Reporting

- Create a CheckerBugType like “Use-after-free after release call”.
- Messages should be short:
  - For checkLocation: “Use-after-free: field read of possibly freed object.”
  - For checkPreCall: “Use-after-free: passing possibly freed pointer to a function that dereferences it.”
- If using ReleasedByMap, add a note range to the releasing call site to guide the user.
- Prefer PathSensitiveBugReport via generateNonFatalErrorNode to preserve path context.

4) Heuristics and Scope Control

- Known-release table should include at least:
  - { "mptcp_close_ssk", {2} }
  - Optionally: { "kfree", {0} }, { "kvfree", {0} }
- The checker intentionally does not try to model locking; the bug exists even without modeling locks. The main property is “read after a call that may free the same object.”
- We rely on path-sensitivity: warnings will only trigger on paths where a dereference follows a release call without reassignment clearing the ReleasedMap entry.

5) Utilities Used

- getMemRegionFromExpr to obtain regions from arguments/bases.
- findSpecificTypeInParents to detect dereference AST contexts (MemberExpr, UnaryOperator, ArraySubscriptExpr).
- functionKnownToDeref to identify calls that dereference arguments (used in checkPreCall).
- Optionally ExprHasName is not required in this plan.

Summary of Control Flow

- On known release call return: mark arg region (canonical) as released.
- Track pointer aliases via checkBind with canonicalization.
- On any dereference or passing-to-deref-known call: look up the canonical region in ReleasedMap and report if released.

This directly detects the target bug: reading subflow->request_join after calling mptcp_close_ssk(..., subflow), by marking subflow as released in checkPostCall and flagging the subsequent MemberExpr dereference in checkLocation.
