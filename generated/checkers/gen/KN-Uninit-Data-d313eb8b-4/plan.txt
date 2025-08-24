1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedStructs, const MemRegion *, bool)
  - Tracks stack-struct variables that are known to have been fully zeroed. Maps the VarRegion of the stack variable to true when we prove a full memset(…0, sizeof(var/type)) happened. Absence from the map means “not proven fully zeroed”.

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)
  - Tracks simple pointer aliases so we can resolve calls like ptr = &s; … copy_to_user(…, ptr, sizeof(s));. Maps a pointer variable region (LHS) to the VarRegion of the struct variable it points to (base region).

No other traits needed.


2) Callback selection and implementation

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const

Goal: Track aliases from pointer variables to the base VarRegion of a stack struct.

- If Loc is a MemRegion (LHS) and refers to a pointer-typed variable (VarRegion of a local pointer var), and Val is a loc::MemRegionVal:
  - Extract RHS region R from Val.
  - Reduce R to its base-most super region and check if it is a VarRegion (VR) of a local, non-global VarDecl whose type is a RecordType (struct).
  - If yes, update PtrAliasMap[LHS_VarRegion] = VR.
- If Val is a MemRegionVal whose base maps to another pointer var already in PtrAliasMap, transitively update:
  - If RHS region is a VarRegion of pointer type that’s present in PtrAliasMap, set PtrAliasMap[LHS] = PtrAliasMap[RHS].
- Do not add entries for fields or array elements; only map when we know it points to the complete struct object (i.e., the MemRegion is a VarRegion, not FieldRegion/ElementRegion).
- Do not erase entries here; the analyzer will naturally invalidate as paths end.

Helpers:
- Use getAsRegion/isa<VarRegion>/isa<SubRegion> to normalize to base (walk super-regions until top).
- Check VarDecl->isLocalVarDecl() && !VarDecl->hasGlobalStorage().
- Check that the VarDecl type is a RecordType and is a struct (RecordDecl::isStruct()).


B) checkPostCall(const CallEvent &Call, CheckerContext &C) const

Goal: Mark struct variables as fully zeroed when we see a full memset to zero.

- Recognize zeroing functions:
  - Names: "memset", "__builtin_memset", "memzero_explicit", "bzero".
- Extract args: ptr, value (or implicit 0 for bzero), size.
- ptr: Try to resolve the base VarRegion of the struct variable being zeroed:
  - First, get MemRegion from the first argument using getMemRegionFromExpr.
  - If it’s a VarRegion (VR) to a local struct, use it directly.
  - Else if it’s a VarRegion for a pointer variable (pointer-to-void or pointer-to-struct), consult PtrAliasMap to get the aliased struct VarRegion (VR). If found, use that.
  - If the region is FieldRegion/ElementRegion or otherwise not a full VarRegion, bail.
- value: Use EvaluateExprToInt to ensure it is zero (for memset/memzero_explicit). For bzero we can skip value check.
- size: Prove it equals the full size of the struct type:
  - If it is a UnaryExprOrTypeTraitExpr sizeof(T) or sizeof(var), extract the type T and ensure it equals the struct variable’s type (after desugaring).
  - Otherwise try EvaluateExprToInt and compare the integer to ASTContext.getTypeSizeInChars(StructType).getQuantity().
- If both value==0 and size==sizeof(struct), set ZeroedStructs[VR] = true.

Notes:
- We only mark “fully zeroed” on exact, whole-object zeroing. Partial sizes or non-zero fill are ignored.
- This is intentionally conservative to minimize false negatives.


C) checkPreCall(const CallEvent &Call, CheckerContext &C) const

Goal: Detect copies of a possibly partially initialized stack struct (with padding) to user space with a length equal to sizeof(struct).

- Maintain a small internal table of known “copy-out” functions and the indices of the pointer and length parameters:
  - { "nla_put",          LenIdx=2, PtrIdx=3 }
  - { "nla_put_64bit",    LenIdx=2, PtrIdx=3 }
  - { "nla_put_nohdr",    LenIdx=1, PtrIdx=2 }
  - { "copy_to_user",     LenIdx=2, PtrIdx=1 }      // from
  - { "copy_to_user_nofault", LenIdx=2, PtrIdx=1 }
  - { "copy_to_iter",     LenIdx=2, PtrIdx=1 }      // from
- If Call.callee name matches one of the above:
  - Let PtrArg = Call.getArgExpr(PtrIdx), LenArg = Call.getArgExpr(LenIdx).
  - Resolve the struct VarRegion and its type:
    - Try getMemRegionFromExpr(PtrArg).
    - If region is a VarRegion (VR) and the VarDecl is local non-global and of struct type, keep VR.
    - Else if region is a pointer VarRegion, consult PtrAliasMap to find the aliased struct VarRegion (VR).
    - If you cannot resolve a struct VarRegion (i.e., FieldRegion, ElementRegion, globals, heap, non-struct), bail.
  - Check that the length equals the full size of the struct object:
    - If LenArg is a sizeof expression on the same variable/type, accept.
    - Else EvaluateExprToInt and compare to ASTContext.getTypeSizeInChars(StructType).getQuantity().
    - If sizes differ, bail.
  - Check that the struct type actually has implicit padding and is not packed:
    - RecordDecl must be a struct (not union).
    - If RecordDecl has PackedAttr (or isPacked()), bail (no padding).
    - Compute padding with ASTContext.getASTRecordLayout(RD):
      - Interior padding exists if for any field i>0, layout.getFieldOffset(i) > prevFieldEndBit.
      - Trailing padding exists if layout.getSize() > lastFieldEndBit.
      - If neither interior nor trailing padding, bail (no leak risk).
  - If we got here: we are copying exactly sizeof(struct) bytes of a stack struct that has padding.
    - Look up ZeroedStructs[VR]:
      - If present and true, OK (already zeroed); do nothing.
      - Otherwise, report a bug.

Bug report:
- Create a BugType once: “Kernel info leak: copying stack struct with padding”.
- Message: “Stack struct with padding copied with sizeof; missing zero-init (info leak)”.
- Attach the report to the call expression (highlight the length or data argument).
- Use generateNonFatalErrorNode and PathSensitiveBugReport.


3) Key helper logic (internal methods you’ll implement)

- resolveBaseStructVarRegion(const Expr *PtrArg, CheckerContext &C) -> const VarRegion*
  - Try getMemRegionFromExpr(PtrArg).
  - If VarRegion and its VarDecl is a local struct, return it.
  - If VarRegion of a pointer variable, look up in PtrAliasMap to get the struct VarRegion, return it if local struct.
  - Otherwise return nullptr.

- lenMatchesStructSize(const Expr *LenArg, QualType StructTy, CheckerContext &C) -> bool
  - If LenArg is a UnaryExprOrTypeTraitExpr sizeof: check that the operand type (or expr type) equals StructTy after desugaring.
  - Else EvaluateExprToInt and compare to ASTContext.getTypeSizeInChars(StructTy).getQuantity().

- recordHasImplicitPadding(const RecordDecl *RD, ASTContext &AC) -> bool
  - If RD has PackedAttr or isPacked() return false.
  - Use ASTRecordLayout L = AC.getASTRecordLayout(RD).
  - Iterate fields in declaration order:
    - Track lastEnd = 0.
    - For each field i: curOff = L.getFieldOffset(i), curEnd = curOff + AC.getTypeSize(Fi->getType()).
    - If curOff > lastEnd, interior padding detected -> return true.
    - lastEnd = curEnd.
  - If L.getSize() > lastEnd, trailing padding -> return true.
  - Else return false.

- isZeroingCall(const CallEvent &Call) -> bool
  - Name in {"memset", "__builtin_memset", "memzero_explicit", "bzero"}.

- isCopyOutCall(const CallEvent &Call, unsigned &LenIdx, unsigned &PtrIdx) -> bool
  - Lookup in the small table above; fill indices if found.


4) Notes and conservative choices

- We only consider explicit whole-object memset/memzero/bzero as sufficient zero-initialization. Initializers like = {}, designated initializers, or field-by-field assignments are treated as insufficient because padding may remain uninitialized.
- We only warn when:
  - The pointer refers to a complete local stack struct object (not a field/element/global/heap),
  - The length equals exactly sizeof(that struct),
  - And the struct layout has implicit padding (and is not packed).
  These filters keep false positives low and match the target pattern precisely.
- Alias tracking is intentionally simple (pointer variables to stack struct VarRegions via checkBind). That covers common idioms like void *p = &s;. If alias cannot be resolved, the checker stays silent.


5) Chosen callbacks summary

- checkBind: build PtrAliasMap.
- checkPostCall: detect full zeroing of a stack struct and mark ZeroedStructs.
- checkPreCall: detect copy-out-by-sizeof to user APIs, verify padding, and report if not zeroed.

This is sufficient to detect the pattern exemplified by tcf_skbmod_dump: passing &opt with sizeof(opt) to nla_put while opt is not explicitly zeroed, and struct type has padding.
