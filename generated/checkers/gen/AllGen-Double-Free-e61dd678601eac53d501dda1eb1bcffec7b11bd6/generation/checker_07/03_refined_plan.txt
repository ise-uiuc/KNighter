Plan to detect “manual kfree of struct member plus later composite/cleanup free” double-free

1) Program state
- Needed: Yes.
- Define the following program state traits to track already-freed members and simple pointer aliases:
  - Freed members (per base object):
    - REGISTER_MAP_WITH_PROGRAMSTATE(FreedFieldPerBaseMap, const MemRegion*, llvm::ImmutableSet<const FieldDecl*>)
      - Key: base object’s MemRegion (e.g., the region of ‘ca’).
      - Value: set of FieldDecl* that have been freed for that base.
    - You will use the set factory from the state context to add/remove FieldDecl* entries.

  - Pointer aliasing to members:
    - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasBaseMap, const MemRegion*, const MemRegion*)
      - pointer variable MemRegion -> base object MemRegion (e.g., p -> ca)
    - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasFieldMap, const MemRegion*, const FieldDecl*)
      - pointer variable MemRegion -> FieldDecl* (e.g., p -> buckets_nouse)

  - Notes:
    - This keeps the state minimal and precise enough to match the concrete pattern:
      - Direct kfree(ca->member) is matched via MemberExpr.
      - kfree(p) where p aliases ca->member is matched via the alias maps.
    - We intentionally do not attempt interprocedural modeling of composite frees; instead we use a small “known composite-free functions” table.

2) Helper utilities
- Use these small helpers internally to normalize and extract information:
  - isKfreeLike(const CallEvent &Call):
    - Return true if callee name in {"kfree", "kvfree", "vfree", "kfree_sensitive"}.
  - isCompositeCleanup(const CallEvent &Call, CompositeSpec &Out):
    - A small hard-coded table for composite/cleanup functions that free certain members of a base object parameter. For this bug:
      - Entry: Name="bch2_dev_buckets_free", BaseParamIndex=0, FreedMembers={"buckets_nouse"}.
    - Out contains BaseParamIndex and the vector of freed field names.
  - getMemberFromExpr(const Expr *E, CheckerContext &C, const MemRegion* &OutBase, const FieldDecl* &OutField):
    - E = argument expression to kfree-like.
    - Find the MemberExpr inside E using findSpecificTypeInChildren<MemberExpr>(E) (after IgnoreParenImpCasts).
    - If found:
      - Field: FD = cast<FieldDecl>(ME->getMemberDecl()).
      - Base: OutBase = getMemRegionFromExpr(ME->getBase(), C) (the region of the base pointer expression, e.g., ‘ca’).
      - Return true.
    - Else return false.
  - getVarRegionFromExpr(const Expr *E, CheckerContext &C):
    - If E is DeclRefExpr to a pointer variable, return its MemRegion via getMemRegionFromExpr(E, C), otherwise nullptr.
  - lookupFieldInPointee(QualType PtrTy, StringRef Name):
    - If PtrTy is pointer to a record, iterate its fields and return FieldDecl* with matching Name, otherwise nullptr.
  - setFreed(State, Base, FD) and wasFreed(State, Base, FD):
    - Get ImmutableSet from FreedFieldPerBaseMap[Base]; check/insert FD and write back.
  - clearAliasFor(State, PtrReg):
    - Remove PtrReg from both PtrAliasBaseMap and PtrAliasFieldMap.

3) Callback selection and implementation

- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
  - Goal: Build simple aliasing: pointer variable = struct_member_pointer.
  - Steps:
    - Identify LHS pointer variable region:
      - If Loc.getAsRegion() returns a MemRegion R and the bound type is a pointer type, proceed.
    - Try to find a MemberExpr in RHS:
      - Use findSpecificTypeInChildren<MemberExpr>(S) to locate a MemberExpr used on RHS.
      - If found:
        - Compute OutBase and OutField via getMemberFromExpr on the RHS expression.
        - If both non-null: set PtrAliasBaseMap[R] = OutBase and PtrAliasFieldMap[R] = OutField.
      - Else if RHS is another pointer variable (DeclRefExpr):
        - If the RHS var has alias entries in {PtrAliasBaseMap, PtrAliasFieldMap}, copy both aliases from RHS var region to LHS var region.
      - Else:
        - Not an alias to a member; call clearAliasFor on LHS region to avoid stale mappings.

- checkPreCall(const CallEvent &Call, CheckerContext &C) const
  - Goal: Catch direct manual frees and detect duplicates.
  - Steps:
    - If !isKfreeLike(Call) return.
    - Extract the free argument expression E0 = Call.getArgExpr(0).
    - Try direct member:
      - If getMemberFromExpr(E0, C, Base, FD) succeeds:
        - Check if wasFreed(State, Base, FD):
          - If yes: report double free.
          - If no: setFreed(State, Base, FD).
        - return.
    - Try alias:
      - If E0 is a DeclRefExpr to pointer variable:
        - PtrReg = getVarRegionFromExpr(E0, C).
        - Lookup Base = PtrAliasBaseMap[PtrReg] and FD = PtrAliasFieldMap[PtrReg].
        - If both exist:
          - Same as above: if already freed -> report; else mark freed.
          - return.
    - Otherwise: do nothing (we only target frees of struct members for this checker).

- checkPostCall(const CallEvent &Call, CheckerContext &C) const
  - Goal: Model composite/cleanup helpers known to free certain members so that:
    - We flag if those members were manually freed earlier.
    - We mark them as freed so that later manual kfree will also be caught.
  - Steps:
    - CompositeSpec CS;
    - If !isCompositeCleanup(Call, CS) return.
    - Get the base parameter expression: EBase = Call.getArgExpr(CS.BaseParamIndex).
    - Compute BaseReg = getMemRegionFromExpr(EBase, C).
    - Get the base’s pointee type (QualType Pointee) from EBase->getType() (pointer to record).
    - For each Name in CS.FreedMembers:
      - FD = lookupFieldInPointee(Pointee, Name).
      - If FD is nullptr, continue (stay conservative).
      - If wasFreed(State, BaseReg, FD) is true:
        - Report double free (member previously freed manually, now freed by composite).
      - Regardless, setFreed(State, BaseReg, FD) to model the composite free.

4) Reporting
- When a double free is detected (either in checkPreCall or checkPostCall):
  - Create a non-fatal error node via C.generateNonFatalErrorNode().
  - Use a PathSensitiveBugReport with a short, clear message:
    - If detected at manual free after composite: "Double free of struct member 'FIELD'."
    - If detected at composite after manual: "Double free: member 'FIELD' already freed before calling 'FUNC'."
  - Add the related expression range (the free argument or the call expression) to the report for clarity.
  - Use std::make_unique<PathSensitiveBugReport>(...).

5) Minimal composite-free knowledge base
- Implement isCompositeCleanup with a small static table:
  - { Name: "bch2_dev_buckets_free", BaseParamIndex: 0, FreedMembers: {"buckets_nouse"} }
- The design is extensible: add more entries if needed.

6) Notes and simplifications
- We intentionally limit aliasing to:
  - Direct “p = ca->member;” or chain “q = p;”.
  - Overwrites of pointer variables clear alias entries.
- We do not try to reconstruct unknown/heap super-regions; matching uses base variable’s MemRegion (e.g., DeclRefExpr for ‘ca’) plus FieldDecl* identity, which is stable and precise in destructor/teardown functions like the target.
- We do not attempt to reason about reinitialization; if the same member is freed, then reallocated and freed again, this checker may warn. This is acceptable for the targeted bug pattern in teardown paths.
