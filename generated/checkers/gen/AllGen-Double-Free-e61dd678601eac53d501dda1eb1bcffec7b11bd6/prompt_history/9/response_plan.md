Plan

1. Program state customization
   - Define three program-state maps:
     - REGISTER_MAP_WITH_PROGRAMSTATE(ObjFreedFieldsMap, const MemRegion*, FieldIdSet)
       - Maps an object base region (struct pointer) to a set of freed fields.
       - FieldIdSet should be an ImmutableSet<const IdentifierInfo*>.
     - REGISTER_MAP_WITH_PROGRAMSTATE(ObjNullifiedFieldsMap, const MemRegion*, FieldIdSet)
       - Maps an object base region to a set of fields that have been set to NULL after free (to suppress false positives when the cleanup helper checks NULL).
     - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
       - Tracks pointer aliases for object bases so we can resolve “base pointer” equivalence (e.g., p2 = p1).
   - Helper routines (as small static functions in the checker):
     - const MemRegion* getRootBaseRegionFromMemberExpr(const MemberExpr *ME, CheckerContext &C)
       - Walk ME->getBase() while it’s a MemberExpr; then call getMemRegionFromExpr on the final base Expr; return canonicalized region (via aliases).
     - const MemRegion* resolveBaseRegionFromArgExpr(const Expr *E, CheckerContext &C)
       - If E contains a MemberExpr, return getRootBaseRegionFromMemberExpr for that ME.
       - Else if E is a DeclRefExpr of an object pointer, return that region.
       - Else if E is AddressOf (&X) where X is a MemberExpr, use the ME’s root base.
     - const IdentifierInfo* getFieldIdFromExpr(const Expr *E)
       - Find a MemberExpr in E (findSpecificTypeInChildren<MemberExpr>(E)), return ME->getMemberDecl()->getIdentifier().
     - const MemRegion* getCanonicalBase(const MemRegion *R, ProgramStateRef State)
       - Follow PtrAliasMap chains until fixed point; return ultimate base.
     - ProgramStateRef addFieldToSet(ProgramStateRef St, MapType &Map, const MemRegion *Base, const IdentifierInfo *FieldId)
       - Utility to load the set for Base, add FieldId using the set’s factory, and store back.
     - bool setContainsField(ProgramStateRef St, MapType &Map, const MemRegion *Base, StringRef FieldName)
       - Load set for Base and check if any IdentifierInfo->getName() equals FieldName.

2. Knowledge base of composite cleanup helpers
   - Hardcode a small static table describing helpers that free specific members of their object argument(s).
   - Structure:
     - struct CompositeCleanupSpec { const char *Name; unsigned ObjParamIndex; llvm::SmallVector<const char*, 4> FreesFields; };
   - Minimal entry (motivated by the patch):
     - { "bch2_free_super", 0, {"buckets_nouse"} }
   - You may add more entries as needed; keep it small and focused to avoid FPs.

3. Callback: checkBind (aliasing and NULL assignments)
   - Track pointer aliases:
     - If Loc refers to a region LHSReg and Val refers to a region RHSReg (both as regions; ignore non-pointer cases), record PtrAliasMap[LHSReg] = RHSReg.
   - Track nullifications of object members:
     - If S’s LHS is a MemberExpr ME (use findSpecificTypeInChildren<MemberExpr>(S)), and RHS is a null pointer constant (Val.isZeroConstant()), then:
       - Base = getRootBaseRegionFromMemberExpr(ME, C); FieldId = ME->getMemberDecl()->getIdentifier().
       - State = addFieldToSet(State, ObjNullifiedFieldsMap, Base, FieldId).
     - Do not touch ObjFreedFieldsMap here.

4. Callback: checkPreCall (record manual frees and detect double frees)
   - Identify kfree-like calls:
     - If callee name is in {"kfree", "kvfree", "kfree_sensitive", "vfree"}:
       - Arg0 = Call.getArgExpr(0).
       - FieldId = getFieldIdFromExpr(Arg0); if null, bail (we only care about freeing object members).
       - Base = resolveBaseRegionFromArgExpr(Arg0, C); if null, bail.
       - CanonBase = getCanonicalBase(Base, State).
       - State = addFieldToSet(State, ObjFreedFieldsMap, CanonBase, FieldId).
       - C.addTransition(State).
   - Detect composite-cleanup frees of already-freed members:
     - Look up callee name in CompositeCleanupSpec table. If found:
       - Get the object parameter index ObjParamIndex; ArgObj = Call.getArgExpr(ObjParamIndex).
       - Base = resolveBaseRegionFromArgExpr(ArgObj, C); if null, bail.
       - CanonBase = getCanonicalBase(Base, State).
       - For each FieldName in FreesFields:
         - If setContainsField(State, ObjFreedFieldsMap, CanonBase, FieldName) is true AND NOT setContainsField(State, ObjNullifiedFieldsMap, CanonBase, FieldName):
           - Report a bug at this call site:
             - Message: "Double free: member ‘FieldName’ freed again by ‘CalleeName’".
             - Node = C.generateNonFatalErrorNode(); emit PathSensitiveBugReport with a short message.
           - Optionally, remove the field from ObjFreedFieldsMap to avoid duplicate reports on the same path.
       - Do not mutate state otherwise.

5. Optional: checkBeginFunction
   - No special initialization needed; state starts empty per function path.

6. Reporting
   - Use std::make_unique<PathSensitiveBugReport> with a short message per Suggestions.
   - Attach the call expression range as the primary location.
   - Only one report per helper call on first matched field.

7. Notes to reduce false positives
   - Only flag when:
     - The first free was a manual kfree-like call on an object member (MemberExpr).
     - The later helper is a known composite cleanup with an entry in the table that includes the same member name.
     - The member has not been NULL-assigned after the manual free (checked via ObjNullifiedFieldsMap).
   - Rely on PtrAliasMap to connect aliases of the object base pointer between the manual free and the cleanup call.

8. How the plan matches the target patch/pattern
   - At kfree(ca->buckets_nouse): record that field "buckets_nouse" of base ‘ca’ is freed.
   - At bch2_free_super(&ca->disk_sb): table says it frees "buckets_nouse" for the same base ‘ca’ (resolved via MemberExpr base of the address-of argument).
   - The checker reports a double free at the helper call, matching the bug fixed by removing the manual kfree.
