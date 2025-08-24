Plan

1. Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer-to-pointer aliases (e.g., alias_var = original_var;). Used to canonicalize different local names that point to the same struct object.
- REGISTER_MAP_WITH_PROGRAMSTATE(FieldAliasMap, const MemRegion*, std::pair<const MemRegion*, IdentifierInfo const*>)
  - Maps a temporary pointer variable (the key MemRegion of the LHS) to a concrete struct-field identity (BaseRegion, FieldName) when a field address/value is propagated into a temp (e.g., p = ca->buckets_nouse;).
- REGISTER_MAP_WITH_PROGRAMSTATE(FreedFieldsMap, const MemRegion*, ImmutableSet<IdentifierInfo const*>)
  - For a given struct “base” pointer region (canonicalized through PtrAliasMap), records the set of member fields that are already freed on the current path.

2. Helper tables
- KnownFreeLike: {"kfree", "kvfree", "vfree", "kfree_sensitive"}.
- KnownCleanupTable:
  - Each entry has:
    - Name: cleanup function name
    - BaseParamIndex: the argument index that is the “this”/struct pointer (usually 0)
    - FreedFields: list of field names that the helper is known to free on that base object
  - Seed with: {"bch2_dev_buckets_free", 0, {"buckets_nouse"}}
- Optional: It’s fine to keep the table minimal and allow users to extend it.

3. Canonicalization helpers (internal utilities)
- canonicalBase(const MemRegion *R, ProgramStateRef State): Follow PtrAliasMap chains to return a stable “root” MemRegion for the base pointer.
- getFieldName(const Expr *E): If E is a MemberExpr, return the IdentifierInfo* of the field (ME->getMemberDecl()->getIdentifier()).
- getBaseRegionFromMember(const MemberExpr *ME, CheckerContext &C): Use getMemRegionFromExpr(ME->getBase(), C) and canonicalize via PtrAliasMap.
- addFreedField(State, BaseRegion, FieldId): Insert FieldId into FreedFieldsMap[BaseRegion] set and return updated State.
- wasFieldFreed(State, BaseRegion, FieldId): Check if FieldId is already in FreedFieldsMap[BaseRegion].

4. checkBeginFunction
- Clear per-function state if you keep any local caches (ProgramState maps persist path-sensitively; no explicit reset needed unless desired).

5. checkBind
- Purpose: track aliases for both struct base pointers and temporary pointer variables holding struct-field values.
- Pointer-to-pointer aliasing:
  - If binding is pointer_var_LHS = pointer_var_RHS, update PtrAliasMap[LHS_region] = canonicalBase(RHS_region).
- Field-to-pointer aliasing:
  - If binding is ptr = <MemberExpr> and the member expr denotes a field access (ca->field or obj.field):
    - Extract FieldName via getFieldName.
    - Compute BaseRegion via getBaseRegionFromMember.
    - Record FieldAliasMap[ptr_region] = (BaseRegion, FieldName).
- Do not modify FreedFieldsMap here.

6. checkPreCall
- Intercept free-like functions
  - Identify free-like by name in KnownFreeLike.
  - Let Arg0 be the pointer argument.
  - Case A: Arg0 is MemberExpr:
    - FieldId = getFieldName(Arg0).
    - BaseRegion = getBaseRegionFromMember(Arg0).
    - If wasFieldFreed(State, BaseRegion, FieldId) -> reportDoubleFree.
    - Else State = addFreedField(State, BaseRegion, FieldId).
  - Case B: Arg0 is not a MemberExpr:
    - Resolve pointer argument region R = getMemRegionFromExpr(Arg0, C).
    - If FieldAliasMap contains R:
      - (BaseRegion, FieldId) = FieldAliasMap[R]; canonicalize BaseRegion via PtrAliasMap.
      - If wasFieldFreed(State, BaseRegion, FieldId) -> reportDoubleFree.
      - Else State = addFreedField(State, BaseRegion, FieldId).
    - Else: ignore (not a struct-field driven free; out of scope).
- Intercept known cleanup helpers
  - Match callee name in KnownCleanupTable.
  - Get the base argument expression at BaseParamIndex and compute BaseRegion via getMemRegionFromExpr + canonicalization.
  - For every FieldName in the entry’s FreedFields:
    - If wasFieldFreed(State, BaseRegion, FieldName) -> reportDoubleFree (free already happened through direct free or earlier helper).
    - Else State = addFreedField(State, BaseRegion, FieldName).
- Use C.addTransition(State) to carry the updated state along paths.

7. Reporting (reportDoubleFree)
- Create a non-fatal error node via generateNonFatalErrorNode(State).
- Message: "Double free of struct field due to overlapping cleanup"
- Optionally add path notes:
  - Where the first free occurred (via a store site note in FreedFieldsMap change if you keep SourceLocation).
  - The second free location (current call).
- Emit with std::make_unique<PathSensitiveBugReport>.

8. Optional refinements
- Null-safety refinement: before reporting on a direct free, if you can prove the argument is definitely NULL on the path, suppress the report. This is optional; keep it simple initially.
- Extend KnownCleanupTable to additional helpers in the codebase if needed.
- Handle both arrow and dot member access; MemberExpr covers both.

9. Callbacks not needed
- checkPostCall, checkLocation, checkBranchCondition, evalCall, evalAssume, checkRegionChanges, checkEndFunction, checkEndAnalysis, checkASTDecl, checkASTCodeBody are unnecessary for the simplest working solution and can be omitted.

Implementation notes
- The approach keys the “freed” set by (canonical base MemRegion, field IdentifierInfo*). This makes it robust to local pointer aliasing via PtrAliasMap and to freeing through temp pointer variables via FieldAliasMap.
- Utility functions used:
  - getMemRegionFromExpr to obtain regions.
  - ExprHasName is not required since we use MemberExpr->getMemberDecl()->getIdentifier().
- Keep the code Linux-oriented by recognizing kfree-family and the provided bch2_dev_buckets_free helper entry.
