Plan: Detect wrong pointer checked for NULL immediately after allocation

1) Program state
- No custom program state is needed. We will pattern-match in the AST around an if-condition and its immediately preceding statement.

2) Callbacks
- Use only checkBranchCondition. This allows us to:
  - Read the expression being checked in an if-condition.
  - Find the surrounding IfStmt.
  - Locate the immediately previous statement in the same CompoundStmt.
  - Verify it is an assignment from a kzalloc-like allocator.
  - Compare the checked pointer with the allocation target.
  - Optionally confirm error-return behavior (eg, returning -ENOMEM) to reduce false positives.

3) Detailed steps for checkBranchCondition
- Step 3.1: Extract the pointer being NULL-checked from the condition.
  - Implement a local helper getCheckedPtrExpr(const Stmt *Condition):
    - Normalize the condition by ignoring implicit casts (IgnoreImpCasts).
    - Handle patterns:
      - UnaryOperator: if (UO_LNot) return inner expr if it has pointer type.
      - BinaryOperator: if (BO_EQ or BO_NE), and one side is null (IntegerLiteral 0, GNUNullExpr, CXXNullPtrLiteralExpr), return the non-null side if it has pointer type.
      - Direct pointer-as-condition: if (E) where E is a pointer expression (after IgnoreImpCasts), return E.
    - Return nullptr if not a standard NULL-check form.
  - If getCheckedPtrExpr returns nullptr, exit.

- Step 3.2: Find the enclosing IfStmt and the immediately previous statement.
  - Use findSpecificTypeInParents<IfStmt>(Condition, C) to get the IfStmt If.
  - Use findSpecificTypeInParents<CompoundStmt>(If, C) to get the surrounding CompoundStmt CS.
  - Iterate CS->body() to locate If; track the previous statement PrevS (must be directly adjacent to If).
  - If no previous statement found (or If is first in the block), exit.

- Step 3.3: Check if the previous statement is an assignment from an allocation call.
  - If PrevS is not a BinaryOperator with opcode BO_Assign, exit.
  - Let LHS = Assign->getLHS()->IgnoreImpCasts(), RHS = Assign->getRHS()->IgnoreImpCasts().
  - Ensure RHS is a CallExpr CE; otherwise exit.
  - Implement a local helper isKernelAllocator(const CallExpr *CE) that matches callee names:
    - Return true for: "kzalloc", "kmalloc", "kcalloc", "kvzalloc", "vzalloc", "devm_kzalloc" (include common zeroing allocators; kzalloc is necessary for the target bug).
  - If not an allocator call, exit.

- Step 3.4: Compare the allocation target with the checked pointer.
  - Let CheckedE = getCheckedPtrExpr(Condition).
  - Compute regions:
    - RegionAlloc = getMemRegionFromExpr(LHS, C).
    - RegionChecked = getMemRegionFromExpr(CheckedE, C).
  - If either region is null (symbolic region not available), fall back to a conservative text comparison:
    - Extract source text of LHS and CheckedE via ExprHasName or Lexer::getSourceText and compare string equality. If equal, consider it correct, else continue.
  - If RegionAlloc equals RegionChecked, it’s a correct check; exit.
  - Optional false-positive mitigation:
    - If both LHS and CheckedE are MemberExpr, check they share the same base region (get base expr of each, compare getMemRegionFromExpr on bases). If they don’t share a base and you want to be conservative, exit. This keeps the checker focused on patterns like dst->thread.sve_state vs dst->thread.za_state.

- Step 3.5: Heuristics to ensure it’s an out-of-memory error check site (to reduce noise).
  - Inspect the IfStmt’s then-branch:
    - Find a ReturnStmt inside the then-branch: use findSpecificTypeInChildren<ReturnStmt>(If->getThen()).
    - If a ReturnStmt exists, check its expression:
      - If ExprHasName(ReturnExpr, "ENOMEM", C) is true, proceed to report.
      - Otherwise, if EvaluateExprToInt returns a negative value, proceed to report.
    - If no return is found, you can optionally look for a goto to an error label, but to keep it simple, require the return heuristic above.

- Step 3.6: Report the bug.
  - Create a BugType once (for example in the checker constructor or lazily) named "Wrong NULL check after allocation".
  - Build an error node with generateNonFatalErrorNode and emit:
    - PathSensitiveBugReport with a short message like: "Wrong pointer checked after allocation; should check the allocated pointer."
    - Highlight the condition range (Condition->getSourceRange()).
    - Optionally add a note pointing to the allocation site (PrevS) like "Allocated here" by adding a range of the RHS call expression.
  - Do not suppress the path; this is a correctness issue.

4) Helper functions to implement in the checker (minimal, local)
- getCheckedPtrExpr(const Stmt *Condition): as described in Step 3.1.
- isNullExpr(const Expr *E): checks for 0 literal or a null literal expression kinds.
- isKernelAllocator(const CallExpr *CE): match function callee names listed in Step 3.3.
- returnsENOMEM(const Stmt *S, CheckerContext &C): find ReturnStmt in S and check for "ENOMEM" with ExprHasName or a negative integral literal with EvaluateExprToInt.

5) Notes and guardrails
- Scope: Only warn when the if-condition is immediately after the allocation assignment within the same CompoundStmt. This mirrors the targeted bug shape and keeps false positives low.
- Expressions: Support both DeclRefExpr and MemberExpr on LHS/condition. Compare MemRegions when possible; fallback to textual comparison if regions are not available.
- Allocators: The core pattern is kzalloc; include a small set of similar allocators to be robust, but require the error-return heuristic (ENOMEM/negative) to fire the diagnostic.
- No pointer alias tracking is necessary for this pattern; the detection focuses on adjacency and mismatched expressions.
