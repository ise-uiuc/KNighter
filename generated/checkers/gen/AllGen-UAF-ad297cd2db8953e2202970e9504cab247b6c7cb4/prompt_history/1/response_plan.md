1) Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrToNetdev, const MemRegion*, const MemRegion*)
  - Maps a pointer variable/region (e.g., adpt) to the owning net_device’s region.
- REGISTER_MAP_WITH_PROGRAMSTATE(NetdevFreedMap, const MemRegion*, char)
  - Marks a net_device region as freed (value = 1). Absence means not freed.

No extra traits/sets are necessary. Alias tracking will be handled by propagating PtrToNetdev in checkBind.

2) Helper utilities (internal to the checker)
- isCallTo(const CallEvent &Call, StringRef Name)
  - Compare callee identifier with Name.
- getCalleeName(const CallEvent &Call)
  - Returns a StringRef of the callee name for debugging and branching.
- getArgRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C)
  - Return MemRegion of Call.getArgExpr(Idx) using getMemRegionFromExpr.
- getLHSRegionFromBind(SVal Loc)
  - From checkBind’s Loc, return the MemRegion for LHS variable.
- getRHSRegionFromBind(SVal Val)
  - From checkBind’s Val, return the MemRegion for RHS (if it is a region).
- getMemberBasePtrRegion(const Stmt *S, CheckerContext &C)
  - If S corresponds to a memory access on a MemberExpr (adpt->...), find the parent MemberExpr using findSpecificTypeInParents<MemberExpr>(S, C), then return MemRegion of the MemberExpr base expression via getMemRegionFromExpr.
- argContainsMemberBasePtrRegion(const Expr *Arg, CheckerContext &C)
  - Find a MemberExpr inside Arg using findSpecificTypeInChildren<MemberExpr>(Arg); if found, return MemRegion of its base expression via getMemRegionFromExpr. If none, return nullptr.

3) Reporting
- reportUAF(const Stmt *Trigger, const MemRegion *NetdevReg, CheckerContext &C)
  - If no error node exists, create one with generateNonFatalErrorNode.
  - Emit a PathSensitiveBugReport with a short message:
    - "use-after-free: net_device private data used after free_netdev()"

4) Callback: checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
- Purpose: Build the PtrToNetdev map both on netdev_priv() assignment and on pointer aliasing.

Implementation specifics:
- Get LHSReg = getLHSRegionFromBind(Loc); if null, return.
- Case A: Binding LHS from netdev_priv(...)
  - If S contains a CallExpr on the RHS (use findSpecificTypeInChildren<CallExpr>(S)):
    - If callee name is "netdev_priv":
      - Get netdevReg = getMemRegionFromExpr(CallExpr->getArg(0), C).
      - If both LHSReg and netdevReg are non-null, set PtrToNetdev[LHSReg] = netdevReg.
- Case B: Pointer alias propagation
  - Get RHSReg = getRHSRegionFromBind(Val).
  - If RHSReg exists and PtrToNetdev has RHSReg -> netdevReg mapping:
    - Set PtrToNetdev[LHSReg] = netdevReg.
- Do not remove mappings on reassignments; latest binding will overwrite.

5) Callback: checkPreCall(const CallEvent &Call, CheckerContext &C) const
- Purpose: Mark free_netdev() and proactively catch uses of freed netdev_priv data when passed as function arguments (including address-of scenarios that may not cause a load).

Implementation specifics:
- If isCallTo(Call, "free_netdev"):
  - netdevReg = getArgRegion(Call, 0, C).
  - If netdevReg, set NetdevFreedMap[netdevReg] = 1.
  - return.
- For every argument i in Call:
  - ArgExpr = Call.getArgExpr(i).
  - basePtrReg = argContainsMemberBasePtrRegion(ArgExpr, C).
    - If basePtrReg:
      - Look up ownerNetdevReg = PtrToNetdev[basePtrReg].
      - If ownerNetdevReg exists and NetdevFreedMap[ownerNetdevReg] == 1:
        - reportUAF(ArgExpr, ownerNetdevReg, C).

6) Callback: checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const
- Purpose: Catch dereferences of private data after free_netdev via member access (adpt->...).

Implementation specifics:
- If !IsLoad and !IsStore, return.
- basePtrReg = getMemberBasePtrRegion(S, C).
  - If null, return.
- ownerNetdevReg = PtrToNetdev[basePtrReg].
  - If none, return.
- If NetdevFreedMap[ownerNetdevReg] == 1:
  - reportUAF(S, ownerNetdevReg, C).

Notes:
- This catches typical adpt->field reads/writes after free_netdev(). The S provided by the engine for loads/stores will have a MemberExpr parent for "->" access, which we extract using findSpecificTypeInParents.
- Even if the access is address-of a field (&adpt->field), checkPreCall’s argument scanning will catch it when the expression is passed to a function. If such an expression appears in a bind (e.g., p = &adpt->field), you can optionally extend checkBind similarly by detecting a MemberExpr on the RHS and checking NetdevFreedMap for the base.

7) Optional refinement (keep simple; not required)
- To avoid duplicate reports, keep a small bug location set in the node, or rely on CSA’s deduplication.
- You may conservatively clear PtrToNetdev entries for a given netdev when it is freed to reduce future noise, but it’s not necessary for correctness.

8) Summary of detection flow
- Build map: adpt_region -> netdev_region when assigning netdev_priv(netdev) to adpt.
- Mark: free_netdev(netdev) sets netdev_region as freed.
- Detect:
  - Any subsequent member access off adpt (loads/stores) => UAF if its owner netdev is freed.
  - Any function argument that contains a member expression based on adpt (including address-of cases) => UAF if its owner netdev is freed.

9) Messages
- Use a concise message:
  - Title: "use-after-free of net_device private data"
  - Description: "use-after-free: net_device private data used after free_netdev()"

This plan uses minimal state (two maps), leverages checkBind for precise origin tracking from netdev_priv, marks free_netdev in checkPreCall, and reports at memory accesses (checkLocation) and argument uses (checkPreCall), which suffices to capture the teardown order bug illustrated by the patch.
