Plan: Detect unsafe freeing of refcounted metadata_dst (should use dst_release instead of metadata_dst_free/kfree)

1) Program State and Class-level tracking
- REGISTER_SET_WITH_PROGRAMSTATE(RefcountedMdSet, const MemRegion*)
  - Tracks metadata_dst objects (their base regions) that have been inserted into skb/refcounted on the current path (via dst_hold or skb_dst_set).
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks aliases between pointers to metadata_dst. Key is the destination region; value is the canonical “root” region of the source.
- Checker-instance flags (class members, not in ProgramState)
  - bool TUUsesMdDstIntoSkb = false;
    - Set to true when we see any use of &…->dst passed to dst_hold or skb_dst_set anywhere in the TU. This supports a TU-level heuristic warning in teardown functions.
  - Optional: Small set of safe-release sites if you want to suppress warnings beside dst_release (not required).

2) Helper predicates/utilities
- isNamedFunc(const CallEvent &Call, StringRef Name)
  - Return true if callee ID exists and matches Name.
- isFreeLike(const CallEvent &Call)
  - Return true for "metadata_dst_free", "kfree", "kfree_sensitive".
- isDstHoldLike(const CallEvent &Call)
  - Return true for "dst_hold".
- isSkbDstSetLike(const CallEvent &Call)
  - Return true for "skb_dst_set".
- isDstReleaseLike(const CallEvent &Call)
  - Return true for "dst_release".
- getRootAlias(State, R)
  - Follows PtrAliasMap transitively to return the canonical root region for R. Default to R if none.
- baseIsMetadataDst(const Expr *Base)
  - Given the base expression of a MemberExpr, check that the (possibly pointer) pointee RecordDecl name is "metadata_dst".
- getMdRegionFromDstAddressArg(const Expr *Arg, CheckerContext &C)
  - If Arg is taking the address-of a field “dst” within a metadata_dst, return the MemRegion of the metadata_dst base:
    - Recognize patterns: &X->dst or &(X->dst) or &X.dst.
    - Unwrap parens/imp-casts and a unary ‘&’. Extract the MemberExpr to field "dst". Verify that the MemberExpr member name == "dst" and that baseIsMetadataDst(MemberExpr->getBase()) is true. Then return getMemRegionFromExpr(MemberExpr->getBase()->IgnoreParenCasts(), C).
  - Return null if not matching.
- getMdRegionFromExprArg(const Expr *Arg, CheckerContext &C)
  - Return MemRegion for Arg (after IgnoreParenCasts/Implicit).
  - Additionally ensure the pointee type of Arg is "struct metadata_dst" (RecordDecl name == "metadata_dst"). If not, return null.
- isNonLocalMdRegion(const MemRegion *R, const LocationContext *LCtx)
  - Heuristic to reduce false positives for frees:
    - Return true if R is a FieldRegion (i.e., struct field), or if it’s under a region that is not a stack VarRegion of the current frame (e.g., a parameter region, captured via FieldRegion->getSuperRegion chain), or a GlobalRegion. Return false for plain stack locals of this function.

3) Mark md_dst as refcounted when installed into skb or explicitly held (checkPreCall)
- In checkPreCall:
  - If isDstHoldLike(Call):
    - Extract argument 0: ArgDst.
    - R = getMdRegionFromDstAddressArg(ArgDst, C). If non-null:
      - State = State->add<RefcountedMdSet>(getRootAlias(State, R));
      - TUUsesMdDstIntoSkb = true.
  - If isSkbDstSetLike(Call):
    - Extract argument 1: ArgDst.
    - Same handling as above (getMdRegionFromDstAddressArg → add to RefcountedMdSet; set TUUsesMdDstIntoSkb = true).
  - If isDstReleaseLike(Call):
    - Extract argument 0: ArgDst.
    - R = getMdRegionFromDstAddressArg(ArgDst, C). If non-null:
      - Remove getRootAlias(State, R) from RefcountedMdSet (best-effort clean-up).
  - Bind the new State back into the context if changed (C.addTransition).

4) Track pointer aliases to metadata_dst (checkBind)
- In checkBind:
  - If both Val and Loc are pointer SVals, and getMdRegionFromExprArg for the RHS expression returns a non-null MemRegion RhsMd:
    - Let L = MemRegion from LHS (Loc).
    - Set PtrAliasMap[L] = getRootAlias(State, RhsMd). This propagates the root metadata_dst region through pointer copies (p = md, q = p, etc.).
  - Do not modify RefcountedMdSet here.

5) Diagnose unsafe frees of metadata_dst (checkPreCall)
- In checkPreCall when isFreeLike(Call) is true:
  - Extract pointer argument (index 0) Arg.
  - R = getMdRegionFromExprArg(Arg, C). If null, return.
  - Root = getRootAlias(State, R).
  - Case A: Path-proven misuse (strong signal)
    - If State->contains<RefcountedMdSet>(Root) is true:
      - Report a bug: “Freeing metadata_dst directly while refs may exist; use dst_release(&…->dst)”
      - Build a bug node with C.generateNonFatalErrorNode() and emit a PathSensitiveBugReport.
      - Optionally, add a note pointing to the hold/set site (the current state lacks path notes; acceptable to skip).
  - Case B: TU-level heuristic (weaker but catches cross-function bugs like the patch)
    - Else if TUUsesMdDstIntoSkb is true AND isNonLocalMdRegion(Root, C.getLocationContext()) is true:
      - Emit the same bug report as above. This flags frees of fields/globals in teardown/cleanup paths, in TUs where we saw md_dst placed into skb/dst (indicating possible outstanding SKB refs).
  - Do not warn if the callee is dst_release (we only check on free-like functions).
  - Do not warn when the arg type is not metadata_dst*.

6) Optional: Handle explicit safe pattern to reduce noise
- If a function uses dst_release(&md->dst) on the same metadata_dst region and we also see no subsequent free-like call with that md in that function, we naturally won’t warn.
- No extra suppression logic required beyond not treating dst_release as a free.

7) Bug reporting
- Use a single, short message:
  - “Freeing metadata_dst directly while refs may exist; use dst_release(&…->dst)”
- Create the report with generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>.
- Attach the CallExpr of the free-like call as the primary location.

8) Selected callbacks and their implementation details
- checkPreCall (core logic)
  - Recognize:
    - dst_hold (arg 0) → mark RefcountedMdSet, TUUsesMdDstIntoSkb = true.
    - skb_dst_set (arg 1) → mark RefcountedMdSet, TUUsesMdDstIntoSkb = true.
    - dst_release (arg 0) → remove from RefcountedMdSet.
    - metadata_dst_free/kfree/kfree_sensitive (arg 0) → run Diagnose (Step 5).
- checkBind (alias tracking)
  - When binding a metadata_dst* value to another pointer region, map dest → root(source) in PtrAliasMap.
- checkASTCodeBody (TU-level mark, optional reinforcement)
  - Not strictly necessary since we set TUUsesMdDstIntoSkb inside checkPreCall the first time we see dst_hold/skb_dst_set during the analysis of any function in the TU.
  - If desired, we can also set TUUsesMdDstIntoSkb by scanning the AST for calls to dst_hold/skb_dst_set with &…->dst argument (using Expr inspection) to catch cases not covered by path exploration (but this is optional).

9) Notes on using the provided utilities
- Use getMemRegionFromExpr to retrieve MemRegion from expressions (both for base metadata_dst and for free arguments).
- Use ExprHasName sparingly; prefer AST/type checks for robustness when identifying “dst” member or “metadata_dst” pointee.
- findSpecificTypeInChildren is helpful if you need to find a MemberExpr under an address-of expression; however, a direct cast chain walk on the expression is usually sufficient.

10) Summary of minimal steps
- Track metadata_dst refcount participation when &…->dst is used in dst_hold or skb_dst_set (checkPreCall).
- Track pointer aliases (checkBind).
- Warn on metadata_dst_free/kfree of a metadata_dst pointer if:
  - It is path-proven to be refcounted (in RefcountedMdSet), or
  - TUUsesMdDstIntoSkb is true and the freed pointer is a non-local field/global (heuristic cross-function case).
- Message: Freeing metadata_dst directly while refs may exist; use dst_release(&…->dst).
