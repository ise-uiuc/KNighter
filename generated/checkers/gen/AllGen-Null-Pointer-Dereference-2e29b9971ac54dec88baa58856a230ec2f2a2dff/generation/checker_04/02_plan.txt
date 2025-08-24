1) Program state
- No custom program state is needed. We can detect this purely from the AST around the if-condition using the provided utilities.

2) Callbacks to use
- checkBranchCondition: Single, central callback to:
  - Recognize NULL-check conditions.
  - Find the immediately previous statement.
  - Verify if that previous statement is an allocation assignment.
  - Compare the checked pointer with the just-allocated pointer.
  - Report if they differ.

3) Detailed implementation

A. Detect and normalize NULL-check conditions (in checkBranchCondition)
- Input: const Stmt *Condition.
- Normalize the condition expression by peeling wrappers:
  - Strip ParenExpr and implicit casts: E = E->IgnoreParenImpCasts().
  - Handle likely/unlikely macro wrappers:
    - If E is a CallExpr with callee named "likely" or "unlikely", set E to its first argument and then strip parens/impcasts again.
- Identify a “negative NULL-check” that typically follows an allocation failure check:
  - Pattern 1: UnaryOperator with opcode UO_LNot: if (!X) ...
    - Extract X as the checked pointer expression (CheckedExpr = X->IgnoreParenImpCasts()).
  - Pattern 2: BinaryOperator with opcode BO_EQ: if (X == 0) or if (X == NULL)
    - One side must be a null constant:
      - Use EvaluateExprToInt or string-based check: ExprHasName(RHS, "NULL", C) or EvaluateExprToInt == 0.
    - Extract the non-constant side as CheckedExpr.
  - Do not match if (X) or (X != NULL/0). Keep the checker conservative and focused on failure checks.
- Ensure CheckedExpr’s type is pointer: CheckedExpr->getType()->isPointerType().
- Save CheckedExpr for comparison.

B. Find the IfStmt and its previous sibling statement
- From Condition, find the enclosing IfStmt:
  - const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C).
  - If not found, return.
- Find the enclosing CompoundStmt (block) that contains IfS:
  - const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IfS, C).
  - If not found, return (cannot locate sibling).
- Locate IfS in CS’s body sequence and fetch the immediately previous statement PrevS:
  - Iterate CS->body() to find IfS; if it’s the first element, return (no previous statement).
  - PrevS = the statement immediately before IfS.

C. Determine if PrevS is an allocation assignment to a pointer target
- Case 1: PrevS is a BinaryOperator with opcode BO_Assign (LHS = RHS):
  - Extract RHS:
    - Find a CallExpr in RHS with findSpecificTypeInChildren<CallExpr>(RHS).
    - If none, return (not an allocation).
  - Check if the callee is a known possibly-NULL allocator:
    - Accept names: "kzalloc", "kmalloc", "kcalloc", "kmalloc_array", "kzalloc_array", "krealloc", "kmemdup".
    - Get callee name via callee’s FunctionDecl->getNameAsString() and compare to the above set.
    - If not in the set, return.
  - Extract the allocation target (AllocatedExpr) = LHS of the assignment (MemberExpr, DeclRefExpr, etc.).
- Case 2: PrevS is a DeclStmt with a single VarDecl that has an initializer:
  - For the VarDecl’s init, look for a CallExpr as above.
  - If callee is a known allocator, then AllocatedExpr is the DeclRefExpr of the declared variable.
- If neither case matches, return (no immediate prior allocation).

D. Compare the checked pointer and the allocation target
- Obtain regions via the provided utility:
  - const MemRegion *AllocReg = getMemRegionFromExpr(AllocatedExpr, C).
  - const MemRegion *CheckedReg = getMemRegionFromExpr(CheckedExpr, C).
- If either region is null, return (cannot compare).
- If CheckedReg == AllocReg, this is correct and we do nothing.
- If CheckedReg != AllocReg, this is suspicious: “wrong pointer checked after allocation”.

E. Reduce false positives by ensuring it’s an error path typical for allocation failure
- Inspect the Then branch of the IfStmt:
  - const Stmt *ThenS = IfS->getThen().
  - Try to find a ReturnStmt in ThenS using findSpecificTypeInChildren<ReturnStmt>(ThenS).
  - If found, check the return expression:
    - Prefer detecting ENOMEM: if ExprHasName(ReturnExpr, "ENOMEM", C) return true.
    - Optionally also accept EvaluateExprToInt to any negative integer if it succeeds (common error returns), but ENOMEM check is sufficient and robust for kernel code.
- If no ReturnStmt found or no ENOMEM hint, skip reporting to remain conservative.

F. Report the bug
- Create an error node with generateNonFatalErrorNode().
- Emit a short and clear message; for example:
  - "Wrong pointer checked after allocation"
- Point the report to the condition expression or the checked expression.
- Use std::make_unique<PathSensitiveBugReport>.

4) Utilities to use
- findSpecificTypeInParents to get IfStmt and CompoundStmt.
- findSpecificTypeInChildren to locate CallExpr and ReturnStmt within statements.
- getMemRegionFromExpr to obtain comparable memory regions from expressions.
- EvaluateExprToInt for detecting literal zero in equality.
- ExprHasName to detect "NULL", "ENOMEM", and handle macro-based returns and wrappers like unlikely().

5) Notes and scope control
- The checker only triggers when:
  - An IfStmt immediately follows an allocation assignment.
  - The If condition is a negative NULL-check.
  - The Then branch indicates an error path likely due to allocation failure (contains a return mentioning ENOMEM).
  - The checked pointer is different from the just-allocated pointer.
- This keeps the checker simple and precise for the intended kernel pattern (e.g., allocating dst->thread.sve_state but checking dst->thread.za_state).
