```
Goal
Detect cases where code allocates memory to a pointer Palloc (e.g., dst->thread.sve_state = kzalloc(...)) and then immediately checks a different pointer Pchk for NULL (e.g., if (!dst->thread.za_state)), which likely indicates checking the wrong pointer after allocation.

1) Program State
- No custom program states are needed. We can detect this pattern purely from the AST structure around the if-condition.

2) Callbacks
- Use only checkBranchCondition. This is sufficient since we want to inspect the if-condition and the previous sibling statement in the same block.

3) Detailed Steps for checkBranchCondition
- Input: const Stmt *Condition, CheckerContext &C

3.1) Identify IfStmt and extract the checked pointer
- Ascend from Condition to the enclosing IfStmt:
  - Use findSpecificTypeInParents<IfStmt>(Condition, C) to get the IfStmt.
  - Bail if not found.
- From the IfStmt, extract the condition expression and detect if it is a NULL-check on a pointer:
  - Supported condition shapes:
    - UnaryOperator ‘!’ applied to a pointer expression E: if (!E)
    - BinaryOperator ‘==’ comparing a pointer expression E with NULL/0: if (E == NULL) or if (E == 0) or if (NULL == E)
    - (Optionally) BinaryOperator ‘!=’ can be handled too; but focus on failure checks: ‘!’ and ‘== NULL’.
  - Implement helper extractNullCheckedPtr(const Expr *Cond, CheckerContext &C) -> const Expr*:
    - For UnaryOperator with opcode UO_LNot: return its subexpression if it's a pointer type.
    - For BinaryOperator with opcode BO_EQ (and optionally BO_NE):
       - If one operand is a null literal (IntegerLiteral 0, GNUNullExpr, CXXNullPtrLiteralExpr) and the other is a pointer-type expression, return the pointer operand.
    - Otherwise return nullptr.
  - Let PchkExpr be the extracted pointer expression, otherwise bail.

3.2) Find the previous statement and see if it is an allocation into some pointer
- Ascend to the immediate CompoundStmt that contains the IfStmt:
  - Use findSpecificTypeInParents<CompoundStmt>(IfStmt, C).
  - Bail if not found.
- Locate the IfStmt within the CompoundStmt’s body and get its previous sibling statement:
  - Iterate the children of the CompoundStmt to find the IfStmt pointer; if index i > 0, let Prev = Body[i-1]. Otherwise bail.
- Normalize Prev to the effective inner expression if it’s wrapped:
  - If Prev is an ExprWithCleanups, get its subexpression.
  - Expect an Expr or an ExprStmt holding a BinaryOperator.
- Check if Prev is an assignment of the form LHS = CallExpr(...):
  - The core pattern we want: BinaryOperator with opcode BO_Assign.
  - RHS should be a CallExpr (the allocator call).
  - LHS should be a pointer-like lvalue (DeclRefExpr, MemberExpr, etc.).
- Verify the callee is a known allocator that returns NULL on failure:
  - Extract the callee name using CE->getDirectCallee()->getNameAsString().
  - Match against a small allowlist: {"kzalloc", "kmalloc", "kcalloc", "kvzalloc", "vzalloc", "kvmalloc", "devm_kzalloc", "devm_kmalloc", "devm_kcalloc"}.
  - If not in the list, bail.

3.3) Compare the pointer being checked vs. the pointer that was allocated
- Obtain MemRegions for both expressions:
  - PallocRegion = getMemRegionFromExpr(LHS_of_assignment, C)
  - PchkRegion   = getMemRegionFromExpr(PchkExpr, C)
- If both regions are non-null and different (pointer-inequality by region pointer), treat this as a mismatch and candidate bug.
- If either region is null (region extraction failed), apply a textual fallback heuristic to reduce false positives:
  - Try to get leaf member names if expressions are MemberExprs (e.g., ".sve_state" vs ".za_state").
  - If that’s not easily accessible, use ExprHasName(LHS, "sve_state"/"za_state") as a fallback:
    - If LHS contains a field name different from the field name in the if-condition, consider it a mismatch.
- Optional sanity checks to further reduce noise:
  - Ensure both expressions are of pointer type (check QualType->isPointerType()).
  - Optionally ensure they share the same base object (if the regions are field regions under the same base), by comparing base regions (Region->getBaseRegion()) if available.

3.4) Report the bug
- If a mismatch is detected:
  - Create a BugType once (e.g., "Wrong NULL check after allocation").
  - Create a non-fatal error node (C.generateNonFatalErrorNode()) and emit a PathSensitiveBugReport or BasicBugReport.
  - Report location: point to the IfStmt condition range to highlight the wrong check.
  - Short message: "Wrong pointer checked after allocation".
  - Optionally add a note/range on the previous assignment to show the allocated target.

4) Notes and Heuristics
- The checker only warns when the if-condition immediately follows the allocation assignment in the same compound block; this minimizes false positives and matches the target bug pattern.
- Focus primarily on failure-style checks: if (!ptr) or if (ptr == NULL). Supporting ‘!= NULL’ is optional.
- The approach is AST-local; no path-sensitive state or alias tracking is needed.

5) Utility Functions Used
- findSpecificTypeInParents<T>(...)
- getMemRegionFromExpr(...)
- ExprHasName(...)

6) Chosen Clang Static Analyzer Hooks
- checkBranchCondition: Core logic implemented here. No other hooks are required.
```
