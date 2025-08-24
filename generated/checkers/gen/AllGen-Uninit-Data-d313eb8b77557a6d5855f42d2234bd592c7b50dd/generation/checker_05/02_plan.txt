1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(StructZeroedMap, const MemRegion*, bool)
  - Meaning: for a stack struct object region, true means we have seen a full-object zeroing (e.g., memset(&obj, 0, sizeof(obj))). If the key is absent, treat it as not zeroed.

- No other traits or alias maps are needed. We will only match address-of the local variable directly at sinks/zeroing calls to keep the checker simple and precise.

2) Helper utilities (internal to the checker)

- getAddrOfLocalVar(const Expr *E) -> const VarDecl*
  - Strip parens and implicit casts. If E is UnaryOperator '&' applied to a DeclRefExpr that refers to a VarDecl with automatic storage (local) and record type (struct/union), return that VarDecl; else return null.

- getVarRegion(const VarDecl *VD, CheckerContext &C) -> const MemRegion*
  - Use State->getLValue(VD, C.getLocationContext()) and getAsRegion() to obtain the VarRegion.

- isZeroingCall(const CallEvent &Call, const Expr* &PtrArg, const Expr* &ValArg, const Expr* &SizeArg) -> bool
  - Return true if callee name is one of: "memset", "__builtin_memset", "memzero_explicit", "bzero".
  - For memset/::__builtin_memset, set PtrArg=arg0, ValArg=arg1, SizeArg=arg2.
  - For memzero_explicit, set PtrArg=arg0, ValArg=null, SizeArg=arg1.
  - For bzero, set PtrArg=arg0, ValArg=null, SizeArg=arg1.

- zeroValueIsConstZero(const Expr *ValArg, CheckerContext &C) -> bool
  - For memset-like functions that have a value argument, use EvaluateExprToInt to check that it equals 0.

- sizeMatchesVarType(const Expr *SizeArg, const VarDecl *VD, CheckerContext &C) -> bool
  - If SizeArg is a UnaryExprOrTypeTraitExpr (sizeof):
    - If sizeof(type): compare the canonical unqualified type to VD->getType() ignoring qualifiers and attributes.
    - If sizeof(expr): inspect the expression; if it’s a DeclRefExpr to VD or an expression with the same type as VD->getType(), accept.
  - Otherwise, fallback heuristic: ExprHasName(SizeArg, VD->getName(), C).
  - Return true if the sizeof likely refers to the same struct object or its type.

- isSinkCall(const CallEvent &Call, unsigned &SizeIdx, unsigned &DataIdx) -> bool
  - Recognize:
    - "nla_put": SizeIdx=2, DataIdx=3
    - "nla_put_64bit": SizeIdx=2, DataIdx=3
    - "copy_to_user": SizeIdx=2, DataIdx=1
    - "copy_to_user_nofault": SizeIdx=2, DataIdx=1
    - "__copy_to_user": SizeIdx=2, DataIdx=1
    - "__copy_to_user_inatomic": SizeIdx=2, DataIdx=1
    - "copy_to_user_iter": SizeIdx=2 (or 3 depending on variant) and DataIdx=1 (use the common 3-arg pattern: dst, src, size)
  - Return true and set indices if matched; otherwise false.

- hasAnyPadding(const VarDecl *VD, CheckerContext &C) -> bool
  - Use ASTContext &Ctx = C.getASTContext().
  - If VD->getType() is not a RecordType, return false.
  - Get RecordDecl *RD = VD->getType()->getAsRecordDecl().
  - If RD is null, return false.
  - Use const ASTRecordLayout &L = Ctx.getASTRecordLayout(RD).
  - Iterate RD’s fields in declaration order:
    - Keep running end-bit offset AccEnd; initially 0.
    - For each FieldDecl F:
      - Get bit offset Ofs = L.getFieldOffset(FIndex).
      - If Ofs > AccEnd -> internal padding exists, return true.
      - AccEnd = Ofs + Ctx.getTypeSize(F->getType()).
  - After loop, if L.getSize() > AccEnd -> tail padding exists, return true.
  - Otherwise return false.

3) Callbacks and behaviors

- checkPreCall(const CallEvent &Call, CheckerContext &C) const
  A) Detect full-object zeroing
  - If isZeroingCall(Call, PtrArg, ValArg, SizeArg):
    - For memset-like calls that have ValArg, require zeroValueIsConstZero(ValArg, C) == true. For the others (memzero_explicit/bzero), no value check needed.
    - Extract the local VarDecl with getAddrOfLocalVar(PtrArg). If null, return.
    - Verify sizeMatchesVarType(SizeArg, VD, C). If false, return.
    - Obtain region: getVarRegion(VD, C).
    - State = State->set<StructZeroedMap>(Region, true); C.addTransition(State).
    - Return.

  B) Detect sinks that copy the whole struct to user/netlink
  - If isSinkCall(Call, SizeIdx, DataIdx):
    - DataE = Call.getArgExpr(DataIdx).
    - Try to get local VarDecl: VD = getAddrOfLocalVar(DataE). If null, return.
    - Ensure the variable is automatic storage and has RecordType (VD->isLocalVarDecl() and VD->getType()->isRecordType()).
    - SizeE = Call.getArgExpr(SizeIdx). If not sizeMatchesVarType(SizeE, VD, C), return.
    - Optional precision filter: if !hasAnyPadding(VD, C), return (avoid false positives when there is no padding).
    - Get region: R = getVarRegion(VD, C).
    - Look up map: Zeroed = State->get<StructZeroedMap>(R); treat absent as false.
    - If Zeroed is not true:
      - Report a bug:
        - Create BugType: "Potential kernel info leak".
        - Generate a non-fatal error node and emit PathSensitiveBugReport with message:
          "Struct with padding copied without memset; possible kernel info leak."
      - Do not change state.

- Other callbacks
  - None required. We purposely avoid checkBind/aliasing to keep it simple and robust for the primary pattern (&local passed directly).

4) Notes for robust matching

- For detecting the local variable in pointer arguments:
  - Accept forms like "&opt", "(void *)&opt", "&(opt)"; strip parens/casts.
  - Do not consider heap pointers; only direct address-of the local struct variable.

- For memset-like detection:
  - Only accept when the size is syntactically bound to the same object/type via sizeof (per sizeMatchesVarType).
  - This guarantees we recognize full-object zeroing that also clears padding.

- For sinks:
  - The checker aims at the high-signal cases where len == sizeof(obj) and data == &obj.
  - This matches the kernel pattern in the provided patch (nla_put with sizeof(opt), &opt).

- False-positive control:
  - Only warn for local stack records.
  - Only warn when record layout actually has padding (hasAnyPadding == true).
  - Only warn when we didn’t see a confirmed full-object zeroing.

5) Bug report

- Message: "Struct with padding copied without memset; possible kernel info leak."
- Location: the call expression of the sink (Call.getOriginExpr()).
- Single BugType for this checker; use PathSensitiveBugReport with a short note pointing to the data argument as the tainted source if possible (track the Expr &opt as a range).
