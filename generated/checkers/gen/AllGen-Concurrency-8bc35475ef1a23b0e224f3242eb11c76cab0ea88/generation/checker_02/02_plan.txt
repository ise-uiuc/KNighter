Plan

1) Program state
- No custom program state is needed. The pattern is purely syntactic/structural around an if-condition and a preceding statement.

2) Callback functions
- Use only checkBranchCondition. This lets us analyze every IfStmt condition and look at its immediate syntactic context and predecessor statement.

3) Implementation steps in checkBranchCondition

Step A: Retrieve the enclosing IfStmt and its condition
- From the incoming Condition, obtain the enclosing IfStmt:
  - const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C).
  - If null or IS->getCond()->IgnoreImplicit() != Condition->IgnoreImplicit(), return.
- Ensure the condition is a logical-and: BinaryOperator with opcode BO_LAnd.
  - const BinaryOperator *BO = dyn_cast<BinaryOperator>(Condition->IgnoreImpCasts()).
  - If not or opcode != BO_LAnd, return.
- Extract the LHS (guard) and RHS (rest) of the logical-and:
  - const Expr *Guard = BO->getLHS()->IgnoreImpCasts();
  - const Expr *Rest = BO->getRHS()->IgnoreImpCasts();

Step B: Sanity-check the guard form (reduce false positives)
- Accept these guard forms:
  - A boolean DeclRefExpr to a variable or parameter (common guard pattern).
  - A negation or simple compare against 0/NULL on a DeclRefExpr.
- If the guard is an arbitrary complex expression (function calls, derefs), skip (return). This keeps the checker focused on “simple boolean guard && uses-of-precomputed-value”.

Step C: Find the immediate previous statement (Prev) to the IfStmt
- Use the parent CompoundStmt of the IfStmt to find its sibling order:
  - const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C); if null, return.
  - Iterate CS->body() to find IS; if found at index i, then if i == 0 return, else Prev = body[i-1].
- Only proceed if Prev is one of:
  - An assignment statement: BinaryOperator with opcode BO_Assign.
  - A declaration with initializer: DeclStmt with exactly one initialized VarDecl.

Step D: Extract the variable defined in Prev and the assigned expression
- For BO_Assign:
  - LHS must be a DeclRefExpr to a local variable (const VarDecl *VD).
  - AssignedExpr = BO->getRHS()->IgnoreImpCasts();
- For DeclStmt:
  - Single VarDecl (const VarDecl *VD) with an initializer.
  - AssignedExpr = VD->getInit()->IgnoreImpCasts();
- If no single local VD or no initializer, return.

Step E: Check that Rest (RHS of &&) actually uses VD
- Implement a small helper bool exprReferencesVar(const Expr *E, const VarDecl *VD) to recursively scan for DeclRefExpr nodes whose getDecl() == VD.
  - If false, return.
- This ensures we are matching: if (guard && (… uses the computed variable …)).

Step F: Check that AssignedExpr is a “risky read”
- Implement helper bool isRiskyReadExpr(const Expr *E, CheckerContext &C):
  - Return true if any of the following holds:
    - E (or a subexpression) contains a dereference: a UnaryOperator with opcode UO_Deref.
    - E contains an ArraySubscriptExpr.
    - E contains a MemberExpr with isArrow() (i.e., ptr->field).
    - Heuristic: E’s source text contains “work_data_bits” (using ExprHasName(E, "work_data_bits")) to catch the kernel-specific pattern even if deref appears nested.
  - Optional stricter heuristic to reduce false positives:
    - If a deref is found, inspect its base expression. If the base is (or is derived from) a parameter (ParmVarDecl) or a global (hasGlobalStorage()), prefer reporting. This targets “shared/concurrent” objects more often than stack locals.
- If none of the risky patterns found, return.

Step G: Emit the report
- If all checks pass, we have:
  - An unconditional risky read computed in Prev.
  - Immediately followed by an if (guard && … uses computed value …).
  - Report: This is exactly the anti-pattern: computing a potentially racy dereference before ensuring the guard short-circuits the condition.
- Create a bug type once (e.g., in the checker constructor or lazily):
  - std::unique_ptr<BugType> BT = std::make_unique<BugType>(this, "Speculative read before guard", "Concurrency");
- Generate a non-fatal error node at Prev or at AssignedExpr.
- Emit a PathSensitiveBugReport with a short message, for example:
  - “Unconditional read occurs before guard; move the dereference under the guarded path.”
- Highlight the AssignedExpr source range in the report.

4) Notes on utilities and helpers
- Use findSpecificTypeInParents to get IfStmt, CompoundStmt.
- Use ExprHasName to cheaply match “work_data_bits” when present (improves catching the target kernel pattern).
- Implement small recursive visitors inside the checker for:
  - exprReferencesVar(E, VD): walk expression children to find DeclRefExpr bound to VD.
  - isRiskyReadExpr(E, C): walk expression to find UO_Deref, ArraySubscriptExpr, MemberExpr(isArrow), or text match on “work_data_bits”.
- Keep the match tight:
  - Immediate previous statement only.
  - Guard must be the LHS of ‘&&’ (short-circuit usage).
  - Computed variable used only on RHS of ‘&&’ (via exprReferencesVar).

5) Optional extensions (can be added later)
- Also flag: Prev computes from a risky read, followed by if (guard) { … uses var … } (without ‘&&’). This is a simpler but still relevant form. You can implement by:
  - In checkBranchCondition, when condition is a simple guard (no ‘&&’), check if Prev defines a variable that is used only in the then-branch (scan the Then body for use; ensure Else either absent or does not use the var).
- Add a small suppression if AssignedExpr clearly refers only to stack-local memory (no globals, no parameters) to further reduce noise.

This minimal plan finds the kernel bug pattern:
- data = *work_data_bits(work); if (from_cancel && uses(data)) { … }
and suggests moving the read inside the from_cancel guarded path.
