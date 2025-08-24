1) Program state
- No custom program state is necessary. This checker is a local, syntactic/data-flow pattern detector around an if-condition. We will not model concurrency nor aliasing.

2) Callback functions and implementation steps
- Use only checkBranchCondition. This is sufficient to inspect if-conditions and their immediate surrounding statements.

Step A: Identify the target if-condition shape
- In checkBranchCondition(const Stmt *Condition, CheckerContext &C):
  - Get the IfStmt that owns this Condition using findSpecificTypeInParents<IfStmt>(Condition, C). If not found, return.
  - Strip parens/implicits from Condition and dyn_cast to BinaryOperator; require opcode BO_LAnd (logical AND). If not &&, return.
  - Let LHS = BO->getLHS()->IgnoreParenImpCasts(), RHS = BO->getRHS()->IgnoreParenImpCasts().

Step B: Heuristically confirm the "guard" on the left
- We want cases where the left side is a guard that must be evaluated first (as in from_cancel).
  - Use ExprHasName(LHS, "cancel", C) to recognize typical guard names in this kernel pattern (e.g., from_cancel). If false, bail early unless the function name hints we are in flush_work:
    - Retrieve the enclosing function: findSpecificTypeInParents<FunctionDecl>(IfStmt, C). If present, require FunctionDecl->getNameAsString() to contain "flush_work". If neither guard-name nor function-name hint matches, return.

Step C: Ensure the right side reads a previously preloaded local variable
- Look for a DeclRefExpr to a local VarDecl used within RHS:
  - Walk RHS to find the first DeclRefExpr referencing a VarDecl (prefer the first encountered; treat that as V). If none found, return.
- Now obtain the immediate previous statement in the same compound block:
  - Get the enclosing CompoundStmt via findSpecificTypeInParents<CompoundStmt>(IfStmt, C). If missing, return.
  - Iterate the CompoundStmt’s body to locate the position of IfStmt; take the previous non-null statement PrevStmt. If none, return.

Step D: Check that PrevStmt computes V by unconditionally reading the shared field
- Two accepted forms:
  1) Assignment statement of the form V = E:
     - dyn_cast<BinaryOperator>(PrevStmt), opcode BO_Assign.
     - LHS must be DeclRefExpr to the same VarDecl V.
     - Let E = RHS->IgnoreParenImpCasts().
  2) Declaration with initializer (e.g., unsigned long V = E):
     - dyn_cast<DeclStmt>(PrevStmt) with a single VarDecl D.
     - D must be the same VarDecl as V, and D->getInit() must exist.
     - Let E = D->getInit()->IgnoreParenImpCasts().

- Heuristically confirm that E likely reads a concurrently updated field:
  - Either:
    - E contains a dereference (findSpecificTypeInChildren<UnaryOperator>(E) with UO_Deref), or
    - E contains a MemberExpr reading a field called "data" (findSpecificTypeInChildren<MemberExpr>(E) and check MemberExpr->getMemberNameInfo().getAsString() == "data"), or
    - ExprHasName(E, "work_data_bits", C) is true, or ExprHasName(E, "->data", C) or ExprHasName(E, ".data", C) is true.
  - And exclude known safe atomic/qualifying reads to limit false positives:
    - If ExprHasName(E, "READ_ONCE", C) or ExprHasName(E, "atomic", C) or ExprHasName(E, "smp_load", C) is true, return (don’t warn).

Step E: Verify that V is used only inside the guarded RHS (optional but helpful noise filter)
- Check that V appears in RHS (it does by construction).
- Optionally, quickly scan the IfStmt’s condition LHS (should not contain V) by searching for DeclRefExpr to V; if found in LHS, return (we only want the value used in the RHS conjunct).

Step F: Report
- If all checks above pass, emit a bug report:
  - Create a BugType once: “Spurious data-race: read before guard”.
  - Create an error node with C.generateNonFatalErrorNode().
  - Point the report range at PrevStmt (the unconditional read), or the E expression if you prefer a tighter range.
  - Message: “Unconditional read of shared field before guard; move the read under the if (guard).”

Notes and utilities used
- Use findSpecificTypeInParents<IfStmt>(...) to get the IfStmt and CompoundStmt context.
- Use ExprHasName(...) to match “work_data_bits”, “->data”, “.data”, and guard hints like “cancel”.
- Use findSpecificTypeInChildren<UnaryOperator> and findSpecificTypeInChildren<MemberExpr> to quickly detect a deref or field access to “data”.
- Keep the pattern strict: the previous statement must be the preload of V. This minimizes false positives and matches the kernel fix pattern precisely.

Summary of chosen callbacks
- checkBranchCondition only:
  - Detects pattern: immediate previous statement preloads a local variable by dereferencing a shared field (like work->data or *work_data_bits(...)), and the if-condition is of the form guard && uses(var), where guard looks like a cancellation flag. Reports that the preload should be moved under the guard to avoid spurious data races.
