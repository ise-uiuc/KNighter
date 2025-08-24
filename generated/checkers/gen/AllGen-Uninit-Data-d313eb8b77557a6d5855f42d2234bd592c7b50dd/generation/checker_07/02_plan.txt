1) Program State

- REGISTER_MAP_WITH_PROGRAMSTATE(PartiallyInitAgg, const VarDecl*, char)
  - Tracks local struct variables declared with a non-zeroing initializer list (designated or with non-zero elements). Presence in this map means “partially initialized aggregate that may contain uninitialized padding.”

- REGISTER_SET_WITH_PROGRAMSTATE(ZeroCleared, const VarDecl*)
  - Tracks local struct variables that have been explicitly zeroed (e.g., memset(&v, 0, sizeof(v)) or memzero_explicit(&v, sizeof(v))). Presence means safe to export (padding cleared).


2) Helper Predicates / Utilities

- isNetlinkExportCall(const CallEvent &Call, unsigned &LenArgIdx, unsigned &DataArgIdx)
  - Return true if callee is one of:
    - nla_put: LenArgIdx = 2, DataArgIdx = 3
    - nla_put_64bit: LenArgIdx = 2, DataArgIdx = 3
  - Keep the list minimal and explicit to reduce false positives.

- isExplicitZeroingCall(const CallEvent &Call)
  - Return an enum/bitmask:
    - 1: memset(ptr, 0, len) where second arg is zero and len fully covers the variable.
    - 2: memzero_explicit(ptr, len) where len fully covers the variable.
    - 3: bzero(ptr, len) where len fully covers the variable.
  - Otherwise return 0.

- getLocalStructVarFromAddrArg(const Expr *ArgE) -> const VarDecl*
  - Strip casts and parens. If it is UnaryOperator(UO_AddrOf) of a DeclRefExpr to a local VarDecl of RecordType, return that VarDecl*, else nullptr.

- sizeofCoversVar(const VarDecl *VD, const Expr *LenExpr, CheckerContext &C) -> bool
  - Try EvaluateExprToInt on LenExpr. If success, compare to C.getASTContext().getTypeSizeInChars(VD->getType()).getQuantity(); accept if Len >= sizeof(var).
  - If evaluation fails, fallback to ExprHasName(LenExpr, VD->getName()) to catch sizeof(var) textual patterns.
  - Return true only if you’re reasonably certain Len equals (or exceeds) the size of the variable.

- isZeroBraceInit(const InitListExpr *ILE) -> bool
  - Return true if:
    - ILE->getNumInits() == 0 (i.e., “= {}”), or
    - ILE->getNumInits() == 1 and that single init is IntegerLiteral(0) without designators (i.e., “= {0}”).
  - Else false.

- isNonZeroingInitList(const InitListExpr *ILE) -> bool
  - Return true if not isZeroBraceInit(ILE). Also treat any designated initializer as non-zeroing.


3) Callbacks and Logic

A) checkPostStmt(const DeclStmt *DS, CheckerContext &C)
- Purpose: Identify local struct variables that are “partially initialized aggregates.”
- For each Decl in DS:
  - If auto VD = dyn_cast<VarDecl>(Decl):
    - Require VD->hasLocalStorage() and VD->getType()->isRecordType().
    - If VD->hasInit():
      - If the init (IgnoreImplicit) is an InitListExpr:
        - If isNonZeroingInitList(ILE):
          - State = State->set<PartiallyInitAgg>(VD, 1).
        - Else (zero-brace init like “= {}” or “= {0}”):
          - Consider these as fully cleared. State = State->add<ZeroCleared>(VD).
      - Else: do nothing here (we only flag init-list patterns in this step).
    - If no initializer: do nothing here (we will only warn when exported and not ZeroCleared).

Rationale: We specifically capture the patch pattern: designated/partial init which doesn’t clear padding.

B) checkPostCall(const CallEvent &Call, CheckerContext &C)
- Purpose: Mark variables explicitly zero-cleared by known APIs.
- If isExplicitZeroingCall(Call):
  - Extract the pointer argument (Arg0 for memset, Arg0 for memzero_explicit, Arg0 for bzero).
  - VD = getLocalStructVarFromAddrArg(Arg0 Expr). If null, return.
  - Ensure sizeofCoversVar(VD, LenExpr, C) is true (for memset, also ensure second argument is const zero via EvaluateExprToInt).
  - State = State->add<ZeroCleared>(VD)
  - Optionally: State = State->remove<PartiallyInitAgg>(VD) to reflect it is now safe.

Notes:
- memset(ptr, 0, len): check Arg1 == 0 and Arg2 covers size.
- memzero_explicit(ptr, len): check Arg1 covers size.
- bzero(ptr, len): check Arg1 covers size.

C) checkPreCall(const CallEvent &Call, CheckerContext &C)
- Purpose: Detect export of a non-zeroed, padded local struct.
- unsigned LenIdx, DataIdx;
- If !isNetlinkExportCall(Call, LenIdx, DataIdx) return.
- Extract DataVar:
  - VD = getLocalStructVarFromAddrArg(Call.getArgExpr(DataIdx)); if null, return.
  - Must be local RecordType.
- Validate length argument:
  - If !sizeofCoversVar(VD, Call.getArgExpr(LenIdx), C): return (not our pattern).
- Check safety:
  - If State->contains<ZeroCleared>(VD): return (already cleared).
  - If !State->contains<PartiallyInitAgg>(VD): return (we only warn for the known risky init pattern).
- Report:
  - Node = C.generateNonFatalErrorNode();
  - If Node:
    - auto R = std::make_unique<PathSensitiveBugReport>(
        BugType("Kernel info leak", "Security"),
        "Struct with padding copied to user without clearing; use memset(0) before nla_put",
        Node);
    - R->addRange(Call.getSourceRange());
    - C.emitReport(std::move(R));

Notes:
- This keeps the checker focused and low-noise: it only warns when a struct was created via a non-zeroing init-list and is then exported via nla_put/nla_put_64bit with sizeof(struct) length, without an intervening explicit zeroing.


4) Optional Refinements (keep simple if not needed)

- Accept additional export functions if needed:
  - e.g., copy_to_user, copy_to_user_iter, nla_put_nohdr, nla_put_string, etc., if they take (len, data). Extend isNetlinkExportCall accordingly, setting proper indices.

- Consider clearing on “= {}” or “= {0}”:
  - The plan already treats these as ZeroCleared to reduce false positives.

- Handle alias of &var via local pointer:
  - If necessary, add a simple alias map (REGISTER_MAP_WITH_PROGRAMSTATE(PtrAlias, const VarDecl*, const VarDecl*)) and track p = &var in checkBind. Then recognize zeroing/exports that use the pointer alias. To keep this checker minimal, skip aliasing unless noise observed.


5) Chosen Simpler Path Justification

- We avoid complex whole-struct initialization tracking. The kernel patch indicates the risky, common pattern: designated/partial initializer for a struct with holes, followed by nla_put(..., sizeof(opt), &opt) without a memset(0). The plan precisely captures that, while allowing explicit zeroing (memset/memzero_explicit) to suppress the warning.
- Using EvaluateExprToInt and ASTContext for size comparison provides robust detection of “sizeof(var)” equivalence without fragile textual heuristics; ExprHasName is used as a fallback only when constant evaluation fails.
