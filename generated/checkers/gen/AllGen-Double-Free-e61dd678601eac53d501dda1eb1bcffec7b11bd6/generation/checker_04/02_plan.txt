Plan

1. Program state
- Register one program state map to remember which struct-field of which object has been freed manually:
  - REGISTER_MAP_WITH_PROGRAMSTATE(ManualFreedMap, std::pair<const MemRegion*, const FieldDecl*>, char)
  - Key: (BaseObjectRegion, FieldDecl*) uniquely identifies the field of a specific object instance.
  - Value: dummy (char) just to mark presence.

- No alias tracking is necessary. The analyzer already propagates pointer equivalence across assignments; getMemRegionFromExpr() on the base pointer expression will yield the same pointee region across aliases on the same path.

2. Known targets
- Free-like functions set:
  - {"kfree", "kvfree", "kfree_sensitive", "vfree"} (extendable)
- Composite cleanup helpers table (function summaries), each entry contains:
  - Function name (callee)
  - Parameter index of the object pointer
  - The list of field names on that object that this helper frees
- Seed the table with:
  - {"bch2_dev_buckets_free", 0, {"buckets_nouse"}}
- Provide small utilities:
  - isFreeLike(const CallEvent &Call)
  - const CleanupSpec* getCleanupSpec(const CallEvent &Call) returning the table entry or nullptr
  - const FieldDecl* resolveFieldDeclFromObjectParam(const Expr *ObjExpr, StringRef FieldName)
    - Steps:
      - Take ObjExpr->IgnoreParenCasts(), get its QualType T.
      - If T is pointer, get pointee PT; if PT is a RecordType, get the RecordDecl.
      - Iterate its FieldDecls to find one with getName() == FieldName; return that FieldDecl*.

3. Callback: checkPreCall
- Goal: record “manual free of object->field”, and detect when a subsequent cleanup helper frees the same field.
- Steps:
  A) Handle manual frees
  - If isFreeLike(Call):
    - Let Arg0 = Call.getArgExpr(0)->IgnoreParenCasts().
    - If Arg0 is a MemberExpr ME (either -> or .):
      - FieldDecl* FD = dyn_cast<FieldDecl>(ME->getMemberDecl()); if null, return.
      - const Expr *BaseE = ME->getBase()->IgnoreParenCasts().
      - const MemRegion *BaseObjReg = getMemRegionFromExpr(BaseE, C); if null, return.
      - Build key = std::make_pair(BaseObjReg, FD).
      - Insert key into ManualFreedMap. Transition to the new state.
      - Optional: If you want to also detect the reverse order, you can in the future add a second map for “freed by helper” and check/report here; but for the target pattern (manual free before helper), this is not needed.
  B) Handle composite cleanup helpers
  - If const CleanupSpec *Spec = getCleanupSpec(Call):
    - Get the object argument: const Expr *ObjE = Call.getArgExpr(Spec->ParamIndex)->IgnoreParenCasts().
    - const MemRegion *BaseObjReg = getMemRegionFromExpr(ObjE, C); if null, return.
    - For each FieldName in Spec->FreedFields:
      - const FieldDecl *FD = resolveFieldDeclFromObjectParam(ObjE, FieldName); if null, continue (type not visible or mismatch).
      - Build key = std::make_pair(BaseObjReg, FD).
      - If key exists in ManualFreedMap:
        - Report bug: “Double free: field '<FieldName>' freed manually and again by '<Spec->FuncName>'.”
        - Create a non-fatal error node and emit a PathSensitiveBugReport anchored at the helper call site.
      - Else: do nothing. We only target the pattern “manual free then helper free”.

4. Other callbacks
- Not required. Do not implement checkBind, checkLocation, etc. Keep the checker simple and focused on this pattern.

5. Bug report
- Use generateNonFatalErrorNode to create a node, then emit a std::make_unique<PathSensitiveBugReport>.
- Short message, e.g.:
  - “Double free: field 'buckets_nouse' freed manually and again by 'bch2_dev_buckets_free'.”
- Point the primary location to the helper call; optionally add a note at the manual free site by storing the SourceRange (MemberExpr or the kfree call) in the state along with the map if you want to enhance diagnostics, but this is optional for a minimal working checker.

6. Notes and matching details
- Only record manual frees when the free argument is a direct MemberExpr; ignore other complex expressions to avoid false positives.
- On resolving FieldDecl for helper entry, match via the actual pointee record of the object parameter at the call site. This allows state keys to use FieldDecl* consistently across both sides (manual and helper).
- Rely on the analyzer’s path-sensitivity to correlate the same object region across aliases and control flow without custom alias maps.

Summary of implementation steps
- Register ManualFreedMap in program state.
- Implement helper predicates isFreeLike and getCleanupSpec (table with {"bch2_dev_buckets_free", 0, {"buckets_nouse"}}).
- Implement resolveFieldDeclFromObjectParam.
- In checkPreCall:
  - If free-like + MemberExpr arg: record (BaseObjReg, FieldDecl) in ManualFreedMap.
  - If cleanup helper: derive (BaseObjReg, FieldDecl) for each listed field and check ManualFreedMap; if present, report.
