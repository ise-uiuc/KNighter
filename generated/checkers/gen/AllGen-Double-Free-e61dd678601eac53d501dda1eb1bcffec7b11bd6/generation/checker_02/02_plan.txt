Plan

1. Program State Customization
- REGISTER_MAP_WITH_PROGRAMSTATE(FreedFieldsMap, const MemRegion*, ImmutableSet<const FieldDecl*>)
  - Tracks, per object instance (base struct pointer region), which member fields have been freed.
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks simple pointer aliases so we can canonicalize different variable names pointing to the same object.

2. Internal Summaries (per-Function)
- Maintain a checker-internal summary table:
  - DenseMap<const FunctionDecl*, llvm::DenseMap<unsigned, ImmutableSet<const FieldDecl*>>>
  - For each function definition, and for each parameter index, record the set of member fields (FieldDecl*) of that parameter which are directly freed inside that function (e.g., via kfree(), kvfree(), vfree(), kfree_sensitive()).
- Helper: bool isFreeLikeName(StringRef N)
  - Return true for {"kfree","kvfree","vfree","kfree_sensitive","kfree_const","kfree_rcu"}.
- Extraction helpers:
  - const FieldDecl* getFreedFieldFromArg(const Expr *E): if E->IgnoreParenCasts() is a MemberExpr, return ME->getMemberDecl()->getCanonicalDecl(); otherwise nullptr.
  - Optional: int getParamIndexOfBase(const MemberExpr *ME): if base of ME is a DeclRefExpr of a ParmVarDecl, return that parameter’s index; else -1.

3. Callback: checkASTCodeBody (function summarization)
- For each FunctionDecl with a body:
  - Walk the body (simple recursive visitor or stack-based traversal).
  - For each CallExpr CE:
    - If callee name is free-like (isFreeLikeName):
      - Let A0 = CE->getArg(0).
      - If getFreedFieldFromArg(A0) returns FD and the base of that MemberExpr is a function parameter Pi (getParamIndexOfBase >= 0):
        - Add FD into summary[ThisFunction][Pi].
  - Store the computed summary in the checker’s summary table.
- Notes:
  - Only direct frees are summarized (no transitive propagation here).
  - This is TU-local and sufficient for the target pattern because component-specific free functions usually directly free their fields.

4. Callback: checkBind (alias tracking)
- When a pointer value is assigned to another pointer variable:
  - If Loc is a MemRegion for a pointer-typed VarRegion Dest, and Val refers to a MemRegion Src (use getAsRegion on Val):
    - Canonicalize Src via PtrAliasMap (find root).
    - Update PtrAliasMap[Dest] = SrcRoot.
- Provide helper MemRegion* canonicalize(const MemRegion *R, ProgramStateRef S): chase PtrAliasMap to its root, default to R if not present.
- Always canonicalize object regions before using them as keys in FreedFieldsMap.

5. Callback: checkPostCall (path-sensitive detection and propagation)
- Case A: Direct free of a member inside the current function
  - If callee is free-like:
    - A0 = Call.getArgExpr(0)
    - If A0 is a MemberExpr ME:
      - FD = ME->getMemberDecl()->getCanonicalDecl()
      - BaseRegion = canonicalize(getMemRegionFromExpr(ME->getBase(), C), State)
      - If BaseRegion is nullptr: return
      - Retrieve FreedSet = State->get<FreedFieldsMap>(BaseRegion) (or empty)
      - If FD already in FreedSet:
        - Report: “Double free of member '<fieldname>'”
      - Else:
        - Add FD to FreedSet and update FreedFieldsMap.
- Case B: Indirect free via calling a function with a summary
  - Let CalleeDecl = dyn_cast_or_null<FunctionDecl>(Call.getDecl())
  - If CalleeDecl exists and has a summary:
    - For each summarized pair (ParamIndex i -> Set S of FieldDecl*):
      - If i < Call.getNumArgs():
        - ArgExpr Ai = Call.getArgExpr(i)
        - BaseRegion = canonicalize(getMemRegionFromExpr(Ai, C), State)
        - If BaseRegion is nullptr: continue
        - FreedSet = State->get<FreedFieldsMap>(BaseRegion)
        - For each FD in S:
          - If FD ∈ FreedSet:
            - Report: “Double free of member '<fieldname>'”
          - Else:
            - Add FD to FreedSet and update FreedFieldsMap.

6. Reporting
- Use generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>.
- BugType: “Double free of struct member”.
- Message:
  - Direct-on-direct: “Double free of member '<fieldname>'”.
  - Via summary: “Double free of member '<fieldname>' via call to '<callee>'”.
- Keep the report location at the second free site (current CallExpr). Keep messages short and clear as requested.

7. Utility Usage
- Use getMemRegionFromExpr to map expressions to regions.
- Use ExprHasName if needed for quick string checks (primarily rely on callee identifiers and FieldDecl names).
- Use findSpecificTypeInChildren or findSpecificTypeInParents only if needed during AST body traversal (not required in the core plan).

8. Minimal Heuristics and Scope
- The checker focuses on patterns: kfree-like(MemberExpr of a parameter’s field) and later component-free call that is summarized to free the same field for the same object instance.
- The alias map is shallow and intra-procedural, adequate for common teardown patterns where the same parameter/variable is used or trivially assigned.
- No global or inter-TU knowledge is assumed beyond what is summarized per TU in checkASTCodeBody.

9. Selected Callbacks Summary
- checkASTCodeBody: Build per-function summaries of which parameter fields are freed.
- checkBind: Track pointer aliases intra-procedurally.
- checkPostCall: Detect direct frees and apply summaries to update FreedFieldsMap; emit reports when freeing an already-freed field.
