Plan

1. Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(IdxTFCheckedMap, SymbolRef, bool)
  - Tracks whether an integer index symbol has been path-checked against TRANSFER_FUNC_POINTS (true = checked).
- Rationale: We only need to remember “this index has been compared to TRANSFER_FUNC_POINTS” to suppress warnings when a proper guard exists. No alias map is needed since we only track scalar index symbols.

2. Helper detections/utilities
- isTFPtsArrayAccess(const ArraySubscriptExpr *ASE, CheckerContext &C)
  - Return true if the subscripted base syntactically refers to the LUT arrays in the pattern (output_tf->tf_pts.red/green/blue). Implement by:
    - Getting the base expression B = ASE->getBase()->IgnoreImpCasts().
    - Use ExprHasName(B, "tf_pts") to filter, and additionally optionally check channel names: ExprHasName(B, "red") || "green" || "blue". If any of these hit, consider it a target array access.
- getArrayCapacityFromBase(const ArraySubscriptExpr *ASE, llvm::APInt &SizeOut)
  - Retrieve the constant element count of the array being indexed:
    - Get the underlying declaration for the member (if base is a MemberExpr, ME->getMemberDecl()) and fetch its QualType.
    - If that QualType is a ConstantArrayType, extract size into SizeOut.
    - Fallback: If the base can be a DeclRefExpr of array (rare here), use the provided getArraySizeFromExpr.
  - If the size is not found (e.g., pointer or unknown), return false and skip capacity-based checks.
- getIndexSymbol(const Expr *IdxE, CheckerContext &C, SymbolRef &SymOut, llvm::APSInt &ConstValOut, bool &IsConst)
  - From State->getSVal(IdxE, LC), try:
    - If EvaluateExprToInt(ConstValOut, IdxE, C) returns true => IsConst = true.
    - Else try to extract SymbolRef from the SVal (nonloc::SymbolVal or via getAsSymbol()) into SymOut and set IsConst = false.
- hasAncestorIfCheckingTFPoints(const Stmt *S, StringRef IndexName, CheckerContext &C)
  - Walk up parents using findSpecificTypeInParents<IfStmt>(...), and if found, check the condition:
    - If ExprHasName(IfStmt->getCond(), "TRANSFER_FUNC_POINTS") AND ExprHasName(IfStmt->getCond(), IndexName), return true.
  - This is a heuristic fallback to suppress warnings when there is any visible guard using TRANSFER_FUNC_POINTS for the same index variable.

3. checkBranchCondition (syntactic guard tracking)
- Goal: Opportunistically mark indexes as “checked” when we see a condition that mentions TRANSFER_FUNC_POINTS on either side.
- Steps:
  - Inspect the branch condition Stmt. If it is a BinaryOperator comparison (BO->isComparisonOp()) and ExprHasName(Cond, "TRANSFER_FUNC_POINTS"):
    - Identify the other side expression that represents the index (the side that does not contain “TRANSFER_FUNC_POINTS”).
    - Extract the symbol for that side via getIndexSymbol(...). If a SymbolRef is found, update:
      - State = State->set<IdxTFCheckedMap>(Sym, true);
      - Ctx.addTransition(State);
  - Handle common forms: i < TRANSFER_FUNC_POINTS, i <= TRANSFER_FUNC_POINTS - 1, TRANSFER_FUNC_POINTS > i, TRANSFER_FUNC_POINTS - 1 >= i. Use ExprHasName to identify which side holds the macro; if the other side is a DeclRefExpr or an arithmetic expression around the index variable, still try to extract its Sym via State->getSVal.
- Note: We do not branch-split here; we conservatively mark “checked” upon sight of an appropriate comparison to avoid false positives.

4. checkPreStmt(const ArraySubscriptExpr *ASE)
- Goal: Detect accesses to output_tf->tf_pts.{red,green,blue}[idx] where idx is not validated against array capacity (TRANSFER_FUNC_POINTS).
- Steps:
  1) Filter: if !isTFPtsArrayAccess(ASE, C), return.
  2) Capacity: llvm::APInt ArrSize; if !getArrayCapacityFromBase(ASE, ArrSize), return (we only act when capacity is known and constant).
  3) Index analysis:
     - Let IdxE = ASE->getIdx()->IgnoreImpCasts().
     - Try constant: llvm::APSInt CVal; if EvaluateExprToInt(CVal, IdxE, C) and (CVal.isNegative() || CVal.uge(ArrSize)):
       - Report: “Index out of bounds for LUT.”
       - Create a node via generateNonFatalErrorNode and emit a PathSensitiveBugReport.
       - Return.
     - Else, try symbol: SymbolRef Sym; extract via getIndexSymbol. If not available, return (not analyzable).
  4) Guarded-by-check suppression:
     - If State->get<IdxTFCheckedMap>(Sym) is true, return (protected by a TRANSFER_FUNC_POINTS comparison on this path).
     - Otherwise, try a heuristic context check: obtain the index variable name (if the index expr is DeclRefExpr, use getDecl()->getName()), and if hasAncestorIfCheckingTFPoints(ASE, IndexName, C) is true, return.
  5) Numeric upper bound inference (optional strengthening):
     - const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C);
     - If Max is non-null and Max->uge(ArrSize):
       - Report: “Index may exceed TRANSFER_FUNC_POINTS.”
       - Return.
  6) Final pattern warning (missing guard):
     - If we reached here, we are accessing the LUT without an observed guard i < TRANSFER_FUNC_POINTS and without a provable safe bound.
     - Report: “Missing ‘i < TRANSFER_FUNC_POINTS’ check before LUT access.”

- Reporting:
  - Use std::make_unique<PathSensitiveBugReport> with a concise message:
    - For definite OOB: “Index out of bounds on LUT access.”
    - For potential OOB / missing check: “Possible OOB: index not validated against TRANSFER_FUNC_POINTS.”
  - Use the ArraySubscriptExpr as the report location (ASE->getExprLoc()).

5. Other callbacks
- None required for this checker. We do not need checkBind, checkLocation, checkPreCall, or checkPostCall.
- No need to clean state in checkEndFunction; the map is path-local and naturally dropped at function end.

6. Notes on conservatism and false positives control
- We:
  - Restrict to array bases that syntactically mention tf_pts (and optionally channel names).
  - Require a known constant array capacity (from the field type) to proceed.
  - Suppress when either:
    - We saw any comparison against TRANSFER_FUNC_POINTS for this symbol (via checkBranchCondition), or
    - There is an enclosing IfStmt whose condition mentions both the index and TRANSFER_FUNC_POINTS (heuristic), or
    - Analyzer can bound the symbol’s maximum below the array capacity (by not hitting Max >= Size).
- This keeps the checker focused on the target patch pattern and avoids spamming unrelated code.
