Plan

1. Program state
- No custom program state is required. We can detect this bug pattern purely from the local AST structure around an if condition.

2. Target callbacks
- Use only checkBranchCondition.

3. Helper recognizers
- isAllocatorCall(const CallExpr* CE):
  - Return true if callee name is one of:
    - kzalloc, kmalloc, kcalloc, kmalloc_array, kcalloc_array, kzalloc_node
    - devm_kzalloc, devm_kmalloc, devm_kcalloc (optional but recommended)
  - Get callee name via CE->getDirectCallee() or callee identifier and compare strings.
- isNullCheckTrueBranch(const Expr* Cond, const Expr*& CheckedPtrExpr, CheckerContext& C):
  - Extracts the pointer being tested for null and indicates that the true-branch corresponds to “pointer is null.”
  - Accepted forms:
    - UnaryOperator ‘!’: if (!E) => true when E is null. Set CheckedPtrExpr = E.
    - BinaryOperator ‘==’: if (E1 == E2) or (E2 == E1) where other side is 0 or NULL (use EvaluateExprToInt for 0 and ExprHasName for “NULL”). Set CheckedPtrExpr to the pointer side.
  - Reject/return false for:
    - ‘!=’ comparisons
    - Plain “if (p)” or other non-nullness tests
- getAssignedLHSFromStmt(const Stmt* S, const Expr*& LHSExprOut, const CallExpr*& AllocCallOut):
  - Handle two immediate-previous-statement cases:
    - BinaryOperator assignment:
      - S is BinaryOperator with opcode BO_Assign.
      - RHS is CallExpr and isAllocatorCall(RHS) true.
      - Set LHSExprOut = LHS, AllocCallOut = RHS.
    - DeclStmt with init:
      - S is DeclStmt, get first VarDecl VD with initializer.
      - Init is CallExpr and isAllocatorCall(Init) true.
      - LHSExprOut = a synthesized DeclRefExpr to VD (or just use the VD in region comparison).
      - AllocCallOut = the initializer CallExpr.
  - Return true only if an allocator call is found on RHS/init.
- regionEqual(const Expr* A, const Expr* B, CheckerContext& C):
  - Use getMemRegionFromExpr(A, C) and getMemRegionFromExpr(B, C).
  - Return true if both regions are non-null and equal.
- thenBranchReturnsENOMEM(const IfStmt* IfS, CheckerContext& C):
  - Locate ReturnStmt inside IfS->getThen() using findSpecificTypeInChildren<ReturnStmt>.
  - If no ReturnStmt, return false.
  - If Return has an expression, check:
    - ExprHasName(ReturnExpr, "ENOMEM", C) is true.
  - If true, return true; else return false.

4. Core detection logic (checkBranchCondition)
- Input: const Stmt* Condition
- Steps:
  1) Ascend to the containing IfStmt using findSpecificTypeInParents<IfStmt>(Condition, C). If not found, return.
  2) Ensure the IfStmt’s true-branch corresponds to a null check:
     - Call isNullCheckTrueBranch(IfS->getCond(), CheckedPtrExpr, C). If false, return.
  3) Ensure the true branch returns -ENOMEM (reduces false positives):
     - If not thenBranchReturnsENOMEM(IfS, C), return.
  4) Find the immediate previous statement in the same CompoundStmt:
     - Ascend to the parent CompoundStmt of the IfStmt using findSpecificTypeInParents<CompoundStmt>(IfS, C).
     - Iterate its body to locate the IfStmt and get the preceding Stmt (prev).
     - If no previous statement or parent not found, return.
  5) From the previous statement, extract an allocator assignment:
     - Use getAssignedLHSFromStmt(prev, LHSExpr, AllocCall).
     - If no allocator assignment found, return.
  6) Compare the expressions:
     - If regionEqual(CheckedPtrExpr, LHSExpr, C) is true, it’s a correct null check; do nothing.
     - Otherwise, report a bug: the code checked a different pointer than the one just allocated.
- Reporting:
  - Create a non-fatal error node via C.generateNonFatalErrorNode().
  - Create a PathSensitiveBugReport with a short message like:
    - “Mismatched NULL check: allocated into X but checked Y”
  - Optionally highlight both the LHSExpr (allocation target) and CheckedPtrExpr (checked expression) source ranges if available.

5. Notes and simplifications
- This checker focuses on the immediate pattern:
  - An allocator assignment in the statement immediately preceding an if.
  - The if condition’s true branch tests for “is NULL” and returns -ENOMEM.
- This narrow window keeps the checker simple and effective for the target bug pattern with low false positives.
- If getMemRegionFromExpr fails for either expression, do not attempt text-based comparison (to avoid false positives); simply skip.
