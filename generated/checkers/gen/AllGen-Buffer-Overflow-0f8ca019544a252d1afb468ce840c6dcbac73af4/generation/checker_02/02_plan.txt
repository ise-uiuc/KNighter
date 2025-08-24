1) Program state
- No custom program state is needed. This checker is a local AST-based pattern detector; we do not track runtime/path-sensitive facts.

2) Callbacks and implementation steps
Use a single AST-level callback to keep the checker simple and robust:
- checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR)

Inside this callback, perform a lightweight AST traversal to find “canonical” count-up for-loops and detect index/size mismatches on array subscripts that use the induction variable.

Step-by-step details:

A. Traverse function body and find canonical count-up for-loops
- Walk the body of D (e.g., RecursiveASTVisitor or a simple recursive walk over Stmts) and visit every ForStmt FS.
- Extract loop components:
  - Init:
    - Accept either:
      - DeclStmt with a single VarDecl having integer type and an initializer equal to 0 (use EvaluateExprToInt on the initializer and require zero).
      - Or BinaryOperator “i = 0” where LHS is a DeclRefExpr to an integer VarDecl and RHS evaluates to 0.
    - Record the induction variable VarDecl* IndVar if found.
  - Cond:
    - Accept the forms:
      - i < Bound
      - i <= Bound
      - Bound > i
      - Bound >= i
    - Normalize to an exclusive upper bound Upper (i ranges in [0, Upper)):
      - i < Bound          => Upper = Bound
      - i <= Bound         => Upper = Bound + 1 (handle APSInt width/sign properly)
      - Bound > i          => Upper = Bound
      - Bound >= i         => Upper = Bound + 1
    - Use EvaluateExprToInt to evaluate Bound on the side opposite to i.
    - If you cannot find IndVar in the condition or cannot evaluate a constant Upper, skip this FS.
  - Inc:
    - Accept “i++”, “++i”, or “i += 1”.
    - If the increment is not a unit step on the same IndVar, skip this FS.

B. Collect array subscript uses of the induction variable inside the loop body
- Recursively visit all ArraySubscriptExpr (ASE) nodes within FS->getBody().
- For each ASE:
  - Check that the index expression uses IndVar directly:
    - Let Idx = ASE->getIdx()->IgnoreParenImpCasts().
    - Accept only if Idx is a DeclRefExpr to IndVar. (Keep it simple; this still covers the target pattern in the patch.)
  - Resolve the array being indexed and its constant bound:
    - Let Base = ASE->getBase()->IgnoreParenImpCasts().
    - Two common cases to support:
      1) Base is a DeclRefExpr of an actual array variable.
         - Use the provided getArraySizeFromExpr to obtain ArraySize (APInt).
      2) Base is a MemberExpr referring to a field of array type.
         - Obtain the FieldDecl* FD = dyn_cast<FieldDecl>(MemberExpr->getMemberDecl()).
         - If FD->getType() is a ConstantArrayType, cast it and get size via cast<ConstantArrayType>(...)->getSize().
    - If neither yields a ConstantArrayType/constant size, skip this ASE (we cannot reason about size).
  - Compare bounds:
    - Convert Upper (APSInt) and ArraySize (APInt) to a common signedness/bit-width for a safe comparison.
    - If Upper > ArraySize, report a bug at this ASE.

C. Optional false-positive suppression: detect a guard inside the loop that bounds i before accesses
- To avoid warning when the body has an early-exit guard like:
  if (i >= ArraySize) { ...; break; }
- Implement a simple guard check:
  - For the loop body CompoundStmt, scan its immediate children statements.
  - If you find an IfStmt whose condition is a comparison between IndVar and a constant value GuardVal such that the comparison is “i >= GuardVal” (or “i == GuardVal”) and GuardVal equals ArraySize, and the Then branch contains a BreakStmt, then consider the body guarded.
  - If guarded is detected, skip reporting for accesses to that same array inside this loop.
- Keep this heuristic simple; do not attempt full path analysis or sibling ordering beyond checking presence. If desired, refine by checking source order using SourceManager::isBeforeInTranslationUnit to ensure the guard appears before the ASE.

D. Reporting
- Create a checker-local BugType (e.g., std::unique_ptr<BugType> BT) with a short name like “Index/size mismatch”.
- When detecting Upper > ArraySize for an ASE, create a BasicBugReport with a concise message, for example:
  - “Index may exceed array bound: loop bound N, array size M”
- Attach the source range of the ASE (ASE->getSourceRange()) and emit the report via BR.emitReport(...).
- Optional: deduplicate within one loop to avoid repeated reports on the same array:
  - Keep a local SmallSet of pairs (ForStmt*, const ValueDecl*) where ValueDecl is the array variable or FieldDecl; only report once per (loop, array).

3) Utility functions usage
- EvaluateExprToInt: to evaluate loop bound and zero init; also to evaluate guard RHS constants.
- getArraySizeFromExpr: to resolve array size for DeclRefExpr bases.
- findSpecificTypeInChildren/findSpecificTypeInParents: not strictly needed; keep traversal explicit and focused for simplicity.
- ExprHasName: not necessary unless you want to special-case macro names; not needed for core detection.

4) Notes and constraints
- This checker intentionally focuses on the simple, common, and high-signal case: direct indexing by the loop induction variable with a constant loop bound and constant array bound.
- It naturally detects the provided bug pattern where i iterates using a larger domain constant (e.g., __DML_NUM_PLANES__) and indexes arrays of a smaller domain (e.g., __DML2_WRAPPER_MAX_STREAMS_PLANES__) without proper validation.
- Path-sensitive modeling (e.g., tracking that an if-condition prevents out-of-bounds) is avoided to keep the implementation minimal; the optional simple guard detection is provided to reduce obvious false positives.
