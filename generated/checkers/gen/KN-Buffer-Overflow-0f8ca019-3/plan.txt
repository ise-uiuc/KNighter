1) Program state
- No custom program state is necessary. This bug can be detected at the array-subscript access site using current path constraints.
- We will only use the existing constraint system via inferSymbolMaxVal and simple AST evaluation via EvaluateExprToInt.

2) Callbacks
- Use only checkLocation (primary) and optionally check::BranchCondition (no state changes, just to allow future suppression). The core detection is in checkLocation.

3) Detailed steps

Step A. Helper utilities (internal to the checker)
- getConstantArraySizeFromBase(const Expr *Base, llvm::APInt &Size, CheckerContext &C):
  - Strip casts/decay: Base = Base->IgnoreParenImpCasts().
  - Handle DeclRefExpr (global/local arrays):
    - Reuse provided getArraySizeFromExpr(Size, Base). If true, return true.
  - Handle MemberExpr (struct/class arrays):
    - If Base is a MemberExpr, fetch FieldDecl = dyn_cast<FieldDecl>(ME->getMemberDecl()).
    - From FieldDecl->getType(), dyn_cast<ConstantArrayType> and extract Size. Return true if found.
  - Handle nested cases like array fields under multiple MemberExprs:
    - Recurse on ME->getBase() until the last MemberExpr that is the array field, but the target array field is the “last” member in the access chain for the ArraySubscriptExpr’s base. Usually, ArraySubscriptExpr base points directly to the array-typed member (pre-decay). If the immediate type is already pointer-decayed, inspect the referenced FieldDecl as above.
  - If none of the above obtains a ConstantArrayType, return false.

- getIndexMax(const Expr *IdxE, CheckerContext &C, llvm::APSInt &MaxIdx, unsigned &KnownKind):
  - Try constant evaluation:
    - If EvaluateExprToInt(MaxIdx, IdxE, C) succeeds, set KnownKind=0 (ExactConst) and return true.
  - Otherwise get the SVal for IdxE: SVal SV = C.getState()->getSVal(IdxE, C.getLocationContext()).
    - If SymbolRef Sym = SV.getAsSymbol(), call inferSymbolMaxVal(Sym, C). If non-null, assign to MaxIdx and set KnownKind=1 (PathMax) and return true.
  - If both fail, return false.

- getLoopUpperBoundIfApplicable(const ArraySubscriptExpr *ASE, const Expr *IdxE, CheckerContext &C, llvm::APSInt &LoopMaxIdx, bool &IsLe):
  - Parent-search: const ForStmt *FS = findSpecificTypeInParents<ForStmt>(ASE, C).
  - If no FS, return false.
  - Check FS->getCond() is a BinaryOperator with op < or <=.
    - Find the “loop var” DeclRefExpr on one side of Cond and check it refers to the same VarDecl as IdxE (if IdxE is a DeclRefExpr). If not a simple DeclRefExpr index, return false.
    - Extract RHS bound expression (the side that is not the loop var).
    - Evaluate RHS via EvaluateExprToInt to an integer UB; if not evaluable, return false.
    - If op is ‘<’, set LoopMaxIdx = UB - 1; IsLe=false.
      If op is ‘<=’, set LoopMaxIdx = UB; IsLe=true.
    - Return true.
  - Otherwise, return false.

Note: getLoopUpperBoundIfApplicable is a fallback to produce a more specific message if inferSymbolMaxVal fails.

Step B. Detection in checkLocation
- Trigger condition: if S (the statement passed to checkLocation) is an ArraySubscriptExpr ASE.
- Compute the array bound N:
  - llvm::APInt ArraySize; if !getConstantArraySizeFromBase(ASE->getBase(), ArraySize, C), bail out (we only warn for known compile-time array sizes).
  - Let N = ArraySize.getZExtValue().

- Analyze the index:
  - const Expr *IdxE = ASE->getIdx()->IgnoreParenImpCasts().
  - First, try path-sensitive bound:
    - llvm::APSInt MaxIdx; unsigned KnownKind;
    - If getIndexMax(IdxE, C, MaxIdx, KnownKind) succeeds:
      - If MaxIdx.uge(N) then report a potential overflow:
        - Rationale: along current path, the analyzer permits the index to be as large as MaxIdx, and if MaxIdx >= N, there exists a feasible state where index >= N (unless further guards exist; those guards would have already refined constraints and reduced MaxIdx).
        - Create a non-fatal error node and emit a short bug report:
          - Title: “Loop bound exceeds array size”
          - Message: “Index may exceed array size (max index >= size).”
          - Optionally add notes:
            - “Array size: N”
            - If KnownKind==0: “Index is constant K”
            - If KnownKind==1: “Max index under current constraints: MaxIdx”
        - Return (avoid duplicate reports).
    - If getIndexMax failed (no constraints available), try to pull a loop bound to compare:
      - llvm::APSInt LoopMaxIdx; bool IsLe;
      - If getLoopUpperBoundIfApplicable(ASE, IdxE, C, LoopMaxIdx, IsLe) succeeds and LoopMaxIdx.uge(N):
        - Report “Loop bound exceeds array size”.
        - Optional macro-based hint (to make it precise for the target pattern):
          - If ExprHasName(FS->getCond(), “__DML_NUM_PLANES__”, C) and ExprHasName(ASE->getBase(), “disp_cfg_to_”, C), include in the message: “Bound uses __DML_NUM_PLANES__ while array is smaller.”
        - Return.

- Heuristic to avoid false positives:
  - If the current path contains a dominating guard like “if (idx >= N) break/return/continue” before ASE, the path constraints will refine MaxIdx < N and the check above will not trigger; no extra work is needed.
  - If MaxIdx is not available and no evaluable loop bound exists, do not warn.

Step C. Optional refinement in check::BranchCondition (not required)
- You do not need to modify program state. This is only for future precision if needed:
  - When seeing a branch condition that compares the index with an array size (e.g., i < N or i >= N), the analyzer already records constraints. No custom work required; thus, you can skip implementing this callback for the first version.

4) Reporting
- Use a single BugType shared across reports (e.g., static std::unique_ptr<BugType> BT).
- Create the node with generateNonFatalErrorNode and emit a PathSensitiveBugReport.
- Keep messages short:
  - Primary: “Index may exceed array size.”
  - Add concise notes (array size N, max index bound, and optionally the macro name if available via ExprHasName).

5) How this catches the target patch pattern
- The loop condition i < __DML_NUM_PLANES__ gives the analyzer a max i of (__DML_NUM_PLANES__ - 1).
- The array fields disp_cfg_to_stream_id[] and disp_cfg_to_plane_id[] have a smaller compile-time size (e.g., __DML2_WRAPPER_MAX_STREAMS_PLANES__).
- Without the added guard (i >= __DML2_WRAPPER_MAX_STREAMS_PLANES__), inferSymbolMaxVal will yield MaxIdx >= N, and the checker reports.
- With the guard present (as in the fix), path constraints at the array access enforce i < N; thus MaxIdx < N and no report is emitted.
