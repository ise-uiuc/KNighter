1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(Priv2DevMap, const MemRegion*, const MemRegion*)
  - Maps a “priv pointer” base region to its owning net_device base region. Key is the base MemRegion of the priv pointer; value is the base MemRegion of the dev passed to netdev_priv().

- REGISTER_SET_WITH_PROGRAMSTATE(FreedDevs, const MemRegion*)
  - Set of net_device base regions that have been freed via free_netdev().

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer aliases (LHS pointer region -> RHS pointer region). This lets us canonicalize both dev and priv pointers across assignments.

Helpers (small, internal):
- resolveAlias(State, R): follow PtrAliasMap chains until a fixed point; return representative region (or R if none).
- getBaseRegionOrSelf(R): if R is a subregion (FieldRegion/ElementRegion), return R->getBaseRegion() repeatedly; else return R. Use MemRegion APIs.
- exprToBaseRegion(E, C): getMemRegionFromExpr(E, C), then getBaseRegionOrSelf on it, then resolveAlias.
- privBaseToDevBase(State, PrivBase): State->get<Priv2DevMap>(PrivBase) if present; otherwise nullptr.
- devIsFreed(State, DevBase): check if FreedDevs contains resolveAlias(DevBase).

2) Callbacks and logic

A) checkPostCall (record relationships + immediate misuse)
- Goal:
  - Learn priv->dev mapping when netdev_priv() is called.
  - Record dev free when free_netdev() is called.
  - Catch netdev_priv() used after free_netdev() immediately.

- Implementation:
  - Get callee name via Call.getCalleeIdentifier()->getName().
  - If callee is "netdev_priv":
    - Arg0 is the dev expression. Compute DevBase = exprToBaseRegion(Arg0, C).
    - RetRegion = getMemRegionFromExpr(Call.getOriginExpr(), C). Compute PrivBase = getBaseRegionOrSelf(RetRegion); then PrivBase = resolveAlias(State, PrivBase).
    - If DevBase is non-null and devIsFreed(State, DevBase) is true:
      - Emit bug: "netdev_priv(dev) after free_netdev".
    - Else if both PrivBase and DevBase are non-null:
      - State = State->set<Priv2DevMap>(PrivBase, DevBase). Bind new state.

  - If callee is "free_netdev":
    - Arg0 is the dev expression. Compute DevBase = exprToBaseRegion(Arg0, C).
    - If DevBase is non-null:
      - State = State->add<FreedDevs>(DevBase). Bind new state.

B) checkBind (track pointer aliases + propagate priv mapping)
- Goal: Record pointer-to-pointer assignments to follow aliases; also propagate known Priv2Dev mapping across aliases to simplify lookups.
- Implementation:
  - If both Loc and Val correspond to pointer-typed memory regions:
    - LHSBase = getBaseRegionOrSelf(Loc.getAsRegion()); LHSBase = resolveAlias(State, LHSBase).
    - RHSBase = getBaseRegionOrSelf(Val.getAsRegion()); RHSBase = resolveAlias(State, RHSBase).
    - If both non-null: State = State->set<PtrAliasMap>(LHSBase, RHSBase).
    - If RHSBase exists in Priv2DevMap mapping to DevBase, also set Priv2DevMap[LHSBase] = DevBase (so that direct lookups on the alias work even without resolving).

C) checkPreCall (detect unsafe uses of priv after free_netdev)
- Goal: Detect when a function known to dereference pointer arguments is called with an argument that is derived from a priv pointer whose owning net_device has already been freed.
- Implementation:
  - Use functionKnownToDeref(Call, DerefParams). If false, return.
  - For each index i in DerefParams:
    - E = Call.getArgExpr(i).
    - ArgBase = exprToBaseRegion(E, C).
    - If ArgBase is null, continue.
    - If PrivDev = State->get<Priv2DevMap>(ArgBase) (direct hit) then DevBase = resolveAlias(State, PrivDev).
      - Else, if ArgBase is a subregion, use getBaseRegionOrSelf before lookup (already done by exprToBaseRegion).
    - If DevBase is non-null and devIsFreed(State, DevBase) is true:
      - Emit bug. Message: "Use of netdev priv after free_netdev".
      - Anchor the report at the current call expression.

  - Populate DerefTable to include at least:
    - cancel_work_sync(arg0)
    - cancel_delayed_work_sync(arg0)
    - flush_work(arg0)
    - flush_delayed_work(arg0)
    - del_timer_sync(arg0)
    - del_timer(arg0)
    - Any other kernel primitives that dereference work/timer structures.
    - Index 0 is typically the param that dereferences the passed work/timer pointer.

D) checkLocation (catch raw dereferences)
- Goal: If there is a direct memory read/write of a priv-derived region after free_netdev(), report.
- Implementation:
  - For Loc.getAsRegion():
    - R = Loc.getAsRegion(); if null, return.
    - Base = getBaseRegionOrSelf(R); Base = resolveAlias(State, Base).
    - If PrivDev = State->get<Priv2DevMap>(Base), then DevBase = resolveAlias(State, PrivDev).
    - If DevBase and devIsFreed(State, DevBase):
      - Emit bug. Message: "Use of netdev priv after free_netdev".
      - Anchor at current Stmt.

3) Reporting

- Use generateNonFatalErrorNode(State) and create PathSensitiveBugReport.
- Bug type: "Use-after-free (net_device private)"
- Short messages:
  - "Use of netdev priv after free_netdev"
  - "netdev_priv(dev) after free_netdev"

4) Notes and simplifications

- Key normalization: Always convert any region to its base region and resolve aliases in every step (dev and priv).
- Priv mapping creation is only via netdev_priv() post-call.
- dev free marking is only via free_netdev() post-call.
- Uses are flagged either:
  - At pre-call on known deref APIs (using functionKnownToDeref).
  - At location deref (loads/stores).
  - Immediately at netdev_priv() call if the dev is already freed.

- This plan intentionally focuses on the simplest reliable path-sensitive signals for the target pattern and avoids complex interprocedural modeling.
