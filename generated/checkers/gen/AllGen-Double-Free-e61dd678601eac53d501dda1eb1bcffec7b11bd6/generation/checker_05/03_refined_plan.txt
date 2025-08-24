Plan

1. Program state customization
- Register sets and maps to track which struct fields were freed and by whom, plus simple aliases:
  - REGISTER_SET_WITH_PROGRAMSTATE(FieldSet, const FieldDecl*)
  - REGISTER_MAP_WITH_PROGRAMSTATE(ManualFreedMap, const MemRegion*, FieldSet)
    - Key: base object region (e.g., the MemRegion of “ca”), Value: set of FieldDecl* that were manually freed.
  - REGISTER_MAP_WITH_PROGRAMSTATE(CleanupFreedMap, const MemRegion*, FieldSet)
    - Key: base object region, Value: set of FieldDecl* that are freed by known cleanup helpers.
  - REGISTER_MAP_WITH_PROGRAMSTATE(VarAliasBaseMap, const MemRegion*, const MemRegion*)
    - Map a pointer variable’s MemRegion to the base object MemRegion if it aliases a struct field pointer.
  - REGISTER_MAP_WITH_PROGRAMSTATE(VarAliasFieldMap, const MemRegion*, const FieldDecl*)
    - Map a pointer variable’s MemRegion to the FieldDecl* it aliases.

2. Helper predicates and utilities
- isFreeLike(const CallEvent &Call):
  - Return true if callee is one of: kfree, kvfree, vfree (keep the initial set minimal; can extend later).
- Known cleanup helper table:
  - Define a static table:
    - Name: "bch2_dev_buckets_free", ParamIndex: 0, FreedFields: {"buckets_nouse"}.
  - isKnownCleanup(const CallEvent &Call, CleanupSpec &Out):
    - If callee name matches an entry, fill Out (callee name, parameter index, vector of field names) and return true.
- getBaseAndFieldFromExpr(const Expr *E, CheckerContext &C, const MemRegion* &OutBase, const FieldDecl* &OutField):
  - Try to resolve the base object and field of an expression that references a struct member pointer.
  - Steps:
    - If E is a MemberExpr (E->IgnoreParenImpCasts()):
      - auto *ME = dyn_cast<MemberExpr>(...); if !ME return false.
      - OutField = dyn_cast<FieldDecl>(ME->getMemberDecl()); if null, return false.
      - OutBase = getMemRegionFromExpr(ME->getBase(), C); return true if not null.
    - Else if E is a DeclRefExpr (variable) or other lvalue-expr:
      - auto *VarReg = getMemRegionFromExpr(E, C); look up VarReg in VarAliasBaseMap and VarAliasFieldMap.
      - If both base and field are found, set OutBase/OutField and return true.
    - Return false otherwise.
- getFieldDeclByNameFromArg(const Expr *Arg, StringRef FieldName, CheckerContext &C) -> const FieldDecl*
  - Obtain the pointee record type of Arg:
    - QualType T = Arg->getType(); if pointer, T = T->getPointeeType(); then get the RecordType and its decl definition.
    - Iterate fields in the RecordDecl to find the field whose getNameAsString() equals FieldName. Return that FieldDecl* or nullptr.
- FieldSet manipulation helpers:
  - addFieldToMap(Map, BaseRegion, FieldDecl*):
    - Retrieve existing FieldSet for BaseRegion (or create empty), add FieldDecl*, write back to the map.
  - containsField(Map, BaseRegion, FieldDecl*) -> bool:
    - Retrieve FieldSet for BaseRegion; return set.contains(FieldDecl*).

3. checkBind
- Purpose: track simple pointer aliases from struct-field pointers into local variables/pointers.
- Implementation steps:
  - Extract LHS and RHS:
    - Get MemRegion* of LHS using Loc (if it’s a VarRegion or FieldRegion) and ensure LHS type is a pointer type.
    - If RHS is a MemberExpr that names a field of a base object (e.g., ca->buckets_nouse):
      - Use getBaseAndFieldFromExpr(RHS, C, BaseReg, FieldDecl).
      - If resolved, set VarAliasBaseMap[LHSVarReg] = BaseReg and VarAliasFieldMap[LHSVarReg] = FieldDecl.
    - Else if RHS is a DeclRefExpr to another variable that already has alias info:
      - Look up RHSVarReg in VarAliasBaseMap and VarAliasFieldMap. If found, propagate both maps onto LHSVarReg.
    - For any other binding, if LHSVarReg exists in alias maps and we’re overwriting it with a non-alias RHS, remove its entries from VarAliasBaseMap and VarAliasFieldMap to avoid stale aliasing.

4. checkPreCall
- Purpose: detect and update state at the moment of freeing or calling a cleanup helper.
- Manual free calls (kfree-like):
  - If isFreeLike(Call):
    - If Call.getNumArgs() < 1, return.
    - Let Arg = Call.getArgExpr(0).
    - Resolve (BaseReg, FieldDecl) via getBaseAndFieldFromExpr(Arg, C, ...). If not resolvable, return (keep checker simple).
    - If containsField(CleanupFreedMap, BaseReg, FieldDecl) is true:
      - Report: "Double free of member also freed by cleanup helper".
      - Generate bug report on this call site.
    - Update state: addFieldToMap(ManualFreedMap, BaseReg, FieldDecl) and transition.
- Known cleanup helper calls:
  - If isKnownCleanup(Call, Spec):
    - Ensure Call.getNumArgs() > Spec.ParamIndex.
    - BaseReg = getMemRegionFromExpr(Call.getArgExpr(Spec.ParamIndex), C). If null, return.
    - For each FieldName in Spec.FreedFields:
      - FD = getFieldDeclByNameFromArg(Call.getArgExpr(Spec.ParamIndex), FieldName, C). If null, continue.
      - If containsField(ManualFreedMap, BaseReg, FD) is true:
        - Report: "Double free: field freed earlier and again by cleanup".
      - Update state: addFieldToMap(CleanupFreedMap, BaseReg, FD) and transition.

5. Reporting
- Use a single BugType (e.g., "Double free of struct member by cleanup helper").
- Keep messages short and clear:
  - For manual free after cleanup: "Double free: this member is also freed by cleanup helper".
  - For cleanup after manual free: "Double free: member already freed earlier".
- Create reports with std::make_unique<PathSensitiveBugReport>.
- Attach the argument Expr as the location range when possible (manual free Arg; cleanup call callee).

6. Optional nuances and constraints
- Scope: Intra-procedural and path-sensitive only; we only warn when the checker can precisely resolve the base region and field. We intentionally skip complex pointer arithmetic or unknown aliases.
- Conservatively handle only direct member frees (ca->field) and simple aliases captured via checkBind. No need to model interprocedural effects besides the known cleanup table.
- Known cleanup table is extensible; initially include:
  - { Name: "bch2_dev_buckets_free", ParamIndex: 0, FreedFields: {"buckets_nouse"} }.
- Free-like extensions can be added later if needed; start with "kfree".

7. Callbacks not used
- checkPostCall, checkBranchCondition, checkLocation, checkBeginFunction, checkEndFunction, checkEndAnalysis, evalCall, evalAssume, checkRegionChanges, checkASTDecl, checkASTCodeBody are not necessary for this minimal checker.
