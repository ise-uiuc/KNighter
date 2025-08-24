Plan

1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(StructZeroedMap, const MemRegion*, bool)
  - Key: base MemRegion of a stack-allocated struct object.
  - Value: true means “all bytes of the struct were explicitly zeroed since declaration” (safe to copy in full); absent or false means “not proven fully zeroed” (potentially leaking padding).

2. Helper predicates/utilities to implement
- getBaseVarRegion(const Expr *E, CheckerContext &C) -> const VarRegion*
  - Use getMemRegionFromExpr(E, C).
  - Call region->getBaseRegion(); then dyn_cast<VarRegion>.
- isLocalRecordVar(const VarRegion *VR) -> bool
  - Check VR is in StackLocalsSpaceRegion and its VarDecl has a RecordType.
- isZeroIntegralExpr(const Expr *E, CheckerContext &C) -> bool
  - Use EvaluateExprToInt; return true when value == 0 and evaluation succeeds.
- isSizeOfVarOrType(const Expr *LenExpr, const VarRegion *VR, CheckerContext &C) -> bool
  - If LenExpr is a UnaryExprOrTypeTraitExpr of kind SizeOf:
    - If it has an argument-expression, check that it is a DeclRefExpr to the same VarDecl as VR.
    - If it is a type operand, check that the type is the same as VR->getValueType().
- recordHasPadding(QualType QT, ASTContext &ACtx) -> bool
  - Use ACtx.getASTRecordLayout(QT->getAs<RecordType>()->getDecl()).
  - Iterate fields: if there is any non-zero byte gap between (prev field end) and (next field start), or if total size in bytes > sum of field sizes plus tail padding is non-zero, return true.
- markZeroed(State, const VarRegion *VR) -> ProgramStateRef
  - Insert (VR, true) into StructZeroedMap.
- wasZeroed(State, const VarRegion *VR) -> Optional<bool>
  - Lookup VR in StructZeroedMap; treat missing as false.

3. Recognize “zeroing” patterns that make a struct safe
A. Zeroing at declaration (checkPostStmt on DeclStmt)
- For each VarDecl in DeclStmt:
  - If it has local storage and record type, and has an initializer:
    - If initializer is an InitListExpr whose elements are all integer/char literals equal to 0 (e.g., “= {0}”):
      - Get VarRegion for the VarDecl and markZeroed.
    - Otherwise, do nothing (designated initializers with runtime values are NOT safe).
  - Note: Do not set any entry when there is no initializer.

B. memset zero over full sizeof(struct) (checkPostCall on CallEvent)
- Detect libc/kernel memset-like calls: function name “memset” (and optionally “__builtin_memset”).
- Extract:
  - dest = arg0; val = arg1; len = arg2.
- If isZeroIntegralExpr(val) and getBaseVarRegion(dest) is a local record VarRegion VR:
  - If isSizeOfVarOrType(len, VR, C):
    - markZeroed(VR).
  - Else, if we can evaluate len to an APSInt and it equals the full size of VR’s type (query via ASTContext.getTypeSizeInChars), also markZeroed.

4. Detect unsafe copy to user space of the entire struct (checkPreCall on CallEvent)
- Maintain a small table of “copy-to-user-like” functions and their src/len parameter indices:
  - nla_put: src index = 3, len index = 2
  - nla_put_64bit: src = 3, len = 2
  - nla_put_nohdr: src = 2, len = 1
  - copy_to_user: src = 1, len = 2
  - copy_to_user_iter: src = 1, len = 2 (approximate; skip if signature mismatch)
- For the matched call:
  - Let SrcExpr and LenExpr be the arguments according to the signature.
  - Obtain VarRegion VR = getBaseVarRegion(SrcExpr, C); require isLocalRecordVar(VR).
  - Check the copy size represents “entire struct”:
    - If isSizeOfVarOrType(LenExpr, VR, C) is true, proceed; else, try to evaluate LenExpr to integer and compare to sizeof(VR->getValueType()) using ASTContext.getTypeSizeInChars; if equal, proceed; otherwise, bail (no warning).
  - Check if the struct type likely contains padding:
    - If recordHasPadding(VR->getValueType(), C.getASTContext()) is false, bail (suppress to avoid noise).
  - Check zeroed state:
    - If wasZeroed(State, VR) is not true, report a bug.

5. Reporting
- On detection in checkPreCall (above):
  - Create a non-fatal error node with C.generateNonFatalErrorNode().
  - Message: “Struct with padding copied to user without full initialization”
  - Use std::make_unique<PathSensitiveBugReport>(...) and C.emitReport(...).
  - Optionally add notes:
    - Point range at the src expression (&var) and len expression (sizeof(var/type)).

6. Optional refinements to reduce false positives
- Ignore copies when source is not an address-of a variable (e.g., raw pointer arithmetic or field address); only proceed when getBaseVarRegion succeeds.
- Reset map entries when region goes out of scope (not strictly necessary: analysis is intra-procedural and the region will not be reused outside the function).
- Accept other zeroing patterns:
  - bzero(&var, sizeof(var)): treat like memset with value 0.
- Be conservative with initializer detection:
  - Only treat “= {0}” (all-zero constant) as safe.
  - Do not treat “= { .f = expr, ... }” as safe even if some constants are zero (padding may remain).

7. Callbacks summary and concrete actions
- checkPostStmt(const DeclStmt *DS, CheckerContext &C)
  - For each local VarDecl of RecordType with an Init:
    - If init is “all zeros” InitListExpr: get VarRegion, markZeroed.
- checkPostCall(const CallEvent &Call, CheckerContext &C)
  - If callee is memset/bzero:
    - If value is 0 and dest is &local struct and len equals sizeof(that struct): markZeroed.
- checkPreCall(const CallEvent &Call, CheckerContext &C)
  - If callee is one of {nla_put, nla_put_64bit, nla_put_nohdr, copy_to_user, copy_to_user_iter}:
    - Extract src and len arg indices, resolve VarRegion for src; ensure local record var.
    - Ensure len represents copying exactly sizeof(struct).
    - Ensure the struct type has padding (recordHasPadding).
    - If not marked zeroed: emit report.

8. Use of provided Utility Functions
- getMemRegionFromExpr for region extraction (then take base VarRegion).
- EvaluateExprToInt for value == 0 and for evaluating len when not sizeof-expression.
- ExprHasName can be used as a fallback (e.g., detecting text “sizeof(” in len) if AST forms are unusual, but prefer AST checks.
- findSpecificTypeInChildren can help find UnaryExprOrTypeTraitExpr under the length argument when needed.
