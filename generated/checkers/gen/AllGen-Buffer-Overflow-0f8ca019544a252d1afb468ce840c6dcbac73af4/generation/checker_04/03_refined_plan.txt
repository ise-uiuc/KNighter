Plan to detect “loop upper bound exceeds array capacity” (mismatched macro sizes)

1) Program state
- No custom program states are necessary. This is a purely AST-based structural check.

2) Callback choice
- Use checkASTCodeBody. We only need a one-shot AST walk per function body to correlate:
  - a for-loop’s index variable and upper bound, and
  - array subscripts inside the loop body that use that variable,
  - the declared constant size of the array being indexed.

3) Detailed steps in checkASTCodeBody
- Walk the body’s AST and visit every ForStmt. For each ForStmt FS do:

  3.1 Extract loop index variable and numeric bounds
  - Parse FS->getInit():
    - Accept either:
      - DeclStmt with a single VarDecl having an initializer (e.g., for (int i = 0; ...))
      - Or a BinaryOperator “i = <init>” (e.g., for (i = 0; ...))
    - Using EvaluateExprToInt, get initial value LB. Proceed only if LB == 0 (to keep the checker simple and avoid false positives on non-zero starting indices).
  - Parse FS->getCond():
    - Expect a BinaryOperator with the loop variable on the LHS (DeclRefExpr to IVar).
    - Supported operators:
      - “<”  => UBExclusive = EvaluateExprToInt(RHS)
      - “<=” => UBExclusive = EvaluateExprToInt(RHS) + 1
    - If evaluation fails or operator is not supported, skip this loop.
  - Record IVar (the VarDecl for the loop index) and the computed LB and UBExclusive.

  3.2 Collect array subscripts using the loop index
  - Recursively traverse FS->getBody() to find all ArraySubscriptExpr nodes ASE.
  - For each ASE:
    - Determine whether its index expression uses IVar:
      - Check if ASE->getIdx()->IgnoreParenImpCasts() is a DeclRefExpr to IVar, or
      - As a slightly more permissive check, walk the index expression and see if any DeclRefExpr refers to IVar (a small helper “containsDeclRefToVar”).
      - If it doesn’t use IVar, skip.
    - Obtain the array capacity Cap from the array base:
      - Base = ASE->getBase()->IgnoreParenImpCasts()
      - If Base is DeclRefExpr to a VarDecl whose type is ConstantArrayType, read ConstantArrayType->getSize() to APInt => Cap.
      - Else if Base is MemberExpr referencing a FieldDecl whose type is ConstantArrayType, read ConstantArrayType->getSize() => Cap.
      - Otherwise (pointers, unknown, or non-constant arrays), skip (we only warn when we are certain).
    - If LB != 0 or UBExclusive not known, skip (already filtered above).

  3.3 Optional guard suppression (simple and local)
  - To reduce false positives when a simple guard exists (like the patch), implement a minimal guard check for the immediate loop body:
    - Find the nearest enclosing CompoundStmt that directly contains ASE (use findSpecificTypeInParents<CompoundStmt>).
    - Within that CompoundStmt, find the statement that lexically contains ASE, and scan the statements before it for an IfStmt that:
      - Has a condition of the form “i >= Cap” or “i < Cap” (try both directions):
        - Parse the If condition as a BinaryOperator with one side being DeclRefExpr to IVar, and the other side a constant integral expression equal to Cap (EvaluateExprToInt on that side).
        - Ops to accept:
          - i >= Cap (then-branch has “break” or “return”): safe-guard; skip warning for ASE inside the rest of the block.
          - i < Cap and ASE is in the then-branch subtree: safe-guard; skip.
      - Use findSpecificTypeInChildren to detect BreakStmt/ReturnStmt in the guarded branch for the “i >= Cap” case, or check subtree containment to ensure ASE is inside the guarded “then” for the “i < Cap” case.
    - If such guard is found before ASE, do not warn for this ASE. If not found, continue.

  3.4 Compare loop upper bound vs array capacity
  - If UBExclusive > Cap:
    - Emit a diagnostic. This is the core mismatch: the loop will drive the index beyond the array’s last valid index.

  3.5 Reporting
  - Create a non-fatal node and emit a BasicBugReport or PathSensitiveBugReport (either is fine here because we’re in checkASTCodeBody).
  - Location: highlight the ArraySubscriptExpr’s index or the ForStmt condition; prefer ASE to point at the actual OOB use site.
  - Message: short and clear, e.g.:
    - “Loop bound exceeds array capacity: index ‘i’ goes up to N-1 but array size is S.”
  - If available, include short notes:
    - “for-condition upper bound: N”
    - “array declared size: S”
    - Use EvaluateExprToInt results and ConstantArrayType size for N and S.

4) Helper routines to implement
- getLoopIndexAndBounds(const ForStmt*, VarDecl*& IVar, llvm::APSInt& LB, llvm::APSInt& UBExclusive):
  - Implements 3.1 using EvaluateExprToInt.
- containsDeclRefToVar(const Expr *E, const VarDecl *V):
  - Walk E’s subtree to find a DeclRefExpr to V.
- getArrayConstSizeFromBase(const Expr *Base, llvm::APInt &Cap):
  - Implements 3.2 for DeclRefExpr/MemberExpr with ConstantArrayType.
- isGuardedBeforeUse(const ArraySubscriptExpr *ASE, const VarDecl *IVar, uint64_t Cap):
  - Implements the lightweight guard detection in 3.3 using:
    - findSpecificTypeInParents<CompoundStmt>
    - findSpecificTypeInParents<IfStmt>
    - findSpecificTypeInChildren<BreakStmt>/findSpecificTypeInChildren<ReturnStmt>
    - EvaluateExprToInt for guard constants.
    - Optional ExprHasName to quickly filter if needed.

5) Notes and simplifications
- We only warn on clear, compile-time provable cases:
  - lower bound 0,
  - condition operators “<” or “<=”,
  - constant array size known via ConstantArrayType,
  - index directly tied to the loop variable.
- This is sufficient to detect the target bug pattern:
  - for (i = 0; i < __DML_NUM_PLANES__; i++) index arrays of size __DML2_WRAPPER_MAX_STREAMS_PLANES__.
- The minimal guard suppression matches the posted fix pattern: an “if (i >= SIZE) { ... break; }” before the data use. If present, we suppress the warning for that ASE.
