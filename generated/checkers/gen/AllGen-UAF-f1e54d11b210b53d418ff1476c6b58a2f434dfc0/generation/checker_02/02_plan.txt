Plan

1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks aliasing between pointers (e.g., local md_dst and field secy->tx_sc.md_dst).
  - Always store the mapping LHSRegion -> RHSRootRegion when we see assignments/binds.

- REGISTER_MAP_WITH_PROGRAMSTATE(DstCarrierMap, const MemRegion*, bool)
  - Marks that a pointer region is a “dst-carrier” (its address-of member ->dst was passed to a dst API). This lets us know the object is a refcounted dst_entry/metadata_dst.

- REGISTER_MAP_WITH_PROGRAMSTATE(DstHoldCountMap, const MemRegion*, unsigned)
  - Best-effort count of dst_hold/dst_release per pointer region. We’ll use this to strengthen the warning when freeing while the pointer has observed holds.

Notes:
- All lookups/updates must use a canonical “root region.” Implement a helper getRootRegion(R, State) that follows PtrAliasMap chains until fixed point (if R maps to R2, and R2 maps to R3, return R3; if no mapping, return R).
- When marking or counting a region, always canonicalize it first via getRootRegion.

2) Callbacks and logic

A) checkPostCall
- Purpose:
  - Detect when a pointer is used with dst APIs and record it as a dst-carrier.
  - Track dst_hold/dst_release counts.
  - Detect frees (metadata_dst_free/kfree) on dst-carriers and report.

- Steps:
  1) Identify callee by name using Call.getCalleeIdentifier()->getName():
     - Holder: "dst_hold"
     - Releaser: "dst_release"
     - User: "skb_dst_set" (2nd arg is dst pointer)
     - Freers: "metadata_dst_free", "kfree"
  2) For holder/releaser/user calls, extract the region of the base pointer of "&ptr->dst":
     - Get the argument index:
       - dst_hold(arg0), dst_release(arg0), skb_dst_set(arg1).
     - On that argument expression, ensure it is taking address of a MemberExpr named "dst". Concretely:
       - Expect UnaryOperator ‘&’ of MemberExpr whose member name is "dst".
       - Get the base expression of the MemberExpr (the “ptr” in ptr->dst).
     - Use getMemRegionFromExpr(baseExpr, C) to obtain BaseRegion. Canonicalize it with getRootRegion.
     - Update program state:
       - DstCarrierMap[Base]=true.
       - If dst_hold: DstHoldCountMap[Base]++.
       - If dst_release and count>0: DstHoldCountMap[Base]--.
  3) For free calls:
     - metadata_dst_free(arg0) or kfree(arg0):
       - Obtain region R0 of the argument via getMemRegionFromExpr(argExpr, C). Canonicalize to Root.
       - Query DstCarrierMap[Root]. If not true, don’t warn (kfree could be other object).
       - If DstCarrierMap[Root] is true then it’s a dst-carrier. This is suspicious to free directly.
         - Strengthen the confidence if DstHoldCountMap[Root] > 0.
       - Emit a bug report. Prefer a short message:
         - “Freeing metadata_dst directly; use dst_release(&p->dst).”
       - Create a non-fatal error node via generateNonFatalErrorNode and emit a PathSensitiveBugReport.

B) checkBind
- Purpose: Track pointer aliases so that uses on locals (e.g., md_dst) match frees on struct fields (e.g., secy->tx_sc.md_dst).

- Steps:
  1) The checker receives S (the Stmt causing the bind). Identify the assignment:
     - Try findSpecificTypeInChildren<BinaryOperator>(S); if found and it’s an assignment LHS=RHS, retrieve LHS and RHS Expr.
     - Else, if it’s a DeclStmt with an initializer, recover the VarDecl’s initializer as RHS and the VarDecl’s reference as LHS.
  2) Get regions:
     - LHSRegion = getMemRegionFromExpr(LHS, C).
     - RHSRegion = getMemRegionFromExpr(RHS, C).
     - If either is null, bail.
  3) Canonicalize RHS via getRootRegion and record alias:
     - PtrAliasMap[LHSRegion] = RHSRoot.
  4) Optional propagation:
     - If DstCarrierMap[RHSRoot] is true, no need to copy that flag; all lookups later will canonicalize.

C) Helpers used in the above
- getRootRegion(const MemRegion* R, ProgramStateRef State):
  - Follow PtrAliasMap until no further mapping.
- isMemberAddrOfDst(const Expr* Arg, const Expr*& OutBaseExpr):
  - Return true if Arg is taking the address of a MemberExpr named "dst" (e.g., &X->dst or &X.dst). If true, set OutBaseExpr to the base X expression.
- isCallee(const CallEvent &Call, StringRef Name):
  - Compare callee identifier name.

3) Reporting
- Use generateNonFatalErrorNode(C) to get an error node.
- Create a PathSensitiveBugReport with a short message:
  - “Freeing metadata_dst directly; use dst_release(&p->dst).”
- Optionally include a note when DstHoldCountMap[Root] > 0:
  - “Pointer passed to dst_hold previously; freeing may cause UAF.”

4) Minimal function recognition and arguments
- dst_hold(arg0): arg0 must be &ptr->dst.
- dst_release(arg0): arg0 must be &ptr->dst.
- skb_dst_set(arg1): arg1 must be &ptr->dst; mark ptr as DstCarrier.
- metadata_dst_free(arg0): arg0 is the metadata_dst* to be freed; if it was marked as a DstCarrier, warn.
- kfree(arg0): same as above, but warn only if arg0 root is a DstCarrier.

5) Notes to reduce false positives
- Only warn on frees if the freed region has been observed as a DstCarrier in the current analysis (i.e., we saw &p->dst passed to dst APIs).
- Don’t require refcount > 0 to warn; seeing metadata_dst_free on a DstCarrier is already risky. If hold count > 0, still warn; otherwise, warn as well (consistent with the fix replacing metadata_dst_free with dst_release).
- This keeps the checker simple and targeted at the kernel pattern from the patch.
