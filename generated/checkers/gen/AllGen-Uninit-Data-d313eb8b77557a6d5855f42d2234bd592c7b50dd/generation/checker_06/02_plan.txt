1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedStructMap, const MemRegion*, bool)
  - Meaning: key is the base region of a stack-allocated struct; value true means “definitely zero-cleared in full size.” Absence or false means unknown/not cleared.
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer aliases: maps a pointer variable’s region (LHS) to the base pointee region (e.g., &opt -> VarRegion(opt)). This allows us to resolve data arguments passed through temporaries.

2) Helper predicates and utilities

- isZeroingFunction(const CallEvent &Call)
  - Return true for memset, __memset, __builtin_memset, memzero_explicit, bzero. Check via Call.getCalleeIdentifier()->getName().
- isUserCopySink(const CallEvent &Call, unsigned &LenIdx, unsigned &DataIdx)
  - Identify sinks and set parameter indices:
    - nla_put(skb, type, len, data): LenIdx=2, DataIdx=3
    - nla_put_64bit(skb, type, len, data, padattr): LenIdx=2, DataIdx=3
    - copy_to_user(to, from, n): LenIdx=2, DataIdx=1
    - __copy_to_user(to, from, n): LenIdx=2, DataIdx=1
    - copy_to_user_iter / _copy_to_iter variants:
      - copy_to_user_iter(to, from, n): LenIdx=2, DataIdx=1
      - _copy_to_iter(addr, bytes, ...): LenIdx=1, DataIdx=0
  - Return false if callee not recognized.
- extractPointeeBaseRegion(const Expr *PtrExpr, CheckerContext &C)
  - Use getMemRegionFromExpr(PtrExpr, C) to get region R.
  - Resolve aliases by repeatedly looking up PtrAliasMap[R] until fixed point; if any step yields a base VarRegion (the original struct region), return it.
  - If syntactically PtrExpr is UnaryOperator ‘&’ of a DeclRefExpr to a VarDecl, also extract its VarRegion directly as a fallback.
- isLocalStructVarRegion(const MemRegion *R)
  - Check R is a VarRegion whose VarDecl is a local variable (isLocalVarDeclOrParm() && hasLocalStorage()) and its type is a RecordType.
- getTypeSizeInBytes(QualType QT, ASTContext &Ctx)
  - Return (size_t) Ctx.getTypeSizeInChars(QT).getQuantity().
- evalSizeArgEqualsVarSize(const Expr *LenE, const VarRegion *VR, CheckerContext &C)
  - Evaluate len constant via EvaluateExprToInt(...). If success:
    - Compute var size via VR->getValueType() and ASTContext.
    - Return true if equal. Otherwise false.
  - If evaluation fails, conservatively return false (to avoid false positives).
- markZeroedIfFullSize(const Expr *Dst, const Expr *ValOrZero, const Expr *Len, CheckerContext &C)
  - For memset-style:
    - Confirm ValOrZero evaluates to zero (EvaluateExprToInt or integer literal 0).
    - Extract base region of Dst with extractPointeeBaseRegion.
    - If base region is a local struct and evalSizeArgEqualsVarSize(Len, VR, C) is true: set ZeroedStructMap[VR]=true in state.

3) Callbacks

- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
  - Track pointer aliases:
    - If Loc is a MemRegion (LHS) and Val is a loc::MemRegionVal (RHS), do:
      - Let L = LHS MemRegion; R = RHS MemRegion.
      - Resolve base for R:
        - If PtrAliasMap contains R -> Base, then map L -> Base.
        - Else map L -> R (direct reference).
    - This handles p = &opt; and p2 = p; by chaining entries.
  - Do not modify ZeroedStructMap here.

- checkPostCall(const CallEvent &Call, CheckerContext &C) const
  - Zeroing recognition:
    - If isZeroingFunction(Call):
      - For memset-like: Dst = arg0, Val = arg1, Len = arg2.
      - For memzero_explicit/bzero-like: Dst = arg0, Len = arg1 (Val is implicitly 0).
      - Apply markZeroedIfFullSize(Dst, Val/implicit0, Len, C) to set ZeroedStructMap[VR]=true.
  - No reporting here.

- checkPreCall(const CallEvent &Call, CheckerContext &C) const
  - Sink detection:
    - unsigned LenIdx, DataIdx; if (!isUserCopySink(Call, LenIdx, DataIdx)) return;
    - Get data expression De = Call.getArgExpr(DataIdx); len expression Le = Call.getArgExpr(LenIdx).
    - Resolve base region VR = dyn_cast<VarRegion>(extractPointeeBaseRegion(De, C)).
    - If VR is null or not a local struct, return (we only flag local stack structs).
    - Check len matches sizeof of the struct: if !evalSizeArgEqualsVarSize(Le, VR, C), return.
    - Query ZeroedStructMap[VR]:
      - If state has VR mapped to true, OK, return.
      - Otherwise (absent or false), emit bug:
        - Create error node via generateNonFatalErrorNode().
        - Report with PathSensitiveBugReport: “Struct not zero-initialized before user copy (may leak stack data).”
        - Attach range of the call (Call.getOriginExpr()) as location.

4) Optional syntactic aids (kept conservative to reduce false positives)

- We intentionally do NOT treat aggregate initializers (e.g., = {0}, designated inits) as “zeroed,” because they may not clear padding/holes. Only explicit zeroing via memset/memzero_explicit/bzero that covers sizeof(variable) qualifies.
- We do not warn if the copy size can’t be evaluated or doesn’t equal sizeof(variable). This avoids false positives when only a subset is copied.

5) Notes on robustness and scope

- This checker focuses on the common kernel pattern: stack struct s; set some fields; nla_put(..., sizeof(s), &s) or copy_to_user(..., &s, sizeof(s)) without a prior full memset/memzero. It warns only when:
  - Data argument resolves to a local struct’s address (directly or via tracked aliases), and
  - The size argument equals sizeof(the struct), and
  - No qualifying zeroing call was seen on that struct beforehand on the current path.
- The maps are path-sensitive. Aliases are tracked only through pointer-to-region bindings via checkBind, sufficient for p = &s; p2 = p; patterns.

6) Minimal bug report details

- Short message: “Copying non-zeroed stack struct to user; zero it first.”
- Category: Kernel Information Leak
- Location: the sink call expression.
- No need for additional notes unless desired (e.g., point to last zeroing site if present).
