1) Program state
- No custom program state is necessary. This checker is a structural/pattern checker that looks for an unconditional read of a shared field immediately before a guarded condition that would have made the read safe.

2) Callback functions
- Use only checkBranchCondition. This is sufficient to (a) recognize the specific guarded if-condition and (b) inspect the immediately preceding statement for the speculative/early read.

3) Detailed steps

Step A: Recognize the guarded condition in checkBranchCondition
- Input: const Stmt *Condition (from the IfStmt condition).
- Find the enclosing IfStmt: use findSpecificTypeInParents<IfStmt>(Condition, C).
- Ensure the statement is actually an IfStmt condition and top-level operator is a logical-and (BO_LAnd). Flatten chained && into a list of conjuncts to correctly identify “leftmost” operand.
- Identify the guard operand:
  - Let GuardExpr be the leftmost operand of the top-level logical-and chain.
  - Use ExprHasName(GuardExpr, "from_cancel", C) to detect the specific guard used in the Linux kernel pattern. If false, bail out early to avoid false positives.
- Identify the “data-dependent” operand:
  - Among the remaining conjuncts (right-side of the leftmost &&), check if any:
    - References a variable commonly used for the pre-read, e.g., ExprHasName(Conjunct, "data", C), or
    - Mentions known accessors of the underlying shared field, e.g., ExprHasName(Conjunct, "work_data_bits", C), or
    - Mentions direct field access pattern, e.g., ExprHasName(Conjunct, "->data", C).
  - If none match, bail out. If the condition contains a call to work_data_bits on the RHS of &&, that is safe (short-circuit) and must not be flagged; we will only warn if we also find a prior unconditional read (see Step B).

Step B: Verify there is an immediately-preceding unconditional read
- From the IfStmt found in Step A, locate its parent CompoundStmt:
  - Use findSpecificTypeInParents<CompoundStmt>(IfStmt, C).
  - Iterate through CompoundStmt body to find the index of this IfStmt; inspect the immediately preceding statement (if any). Skip trivial NullStmt and empty statements.
- Accept either of the following forms for the preceding statement:
  1) DeclStmt with a single VarDecl initialized from the shared field:
     - VarDecl has an initializer Expr Init.
     - The declared variable is most often named “data”; confirm name with VarDecl->getName() == "data" OR the If condition actually uses this variable (by checking a DeclRefExpr to this VarDecl in the If condition).
     - Check Init expression to confirm it is an unsafe read:
       - Matches one of:
         - UnaryOperator ‘*’ applied to a call whose callee name contains “work_data_bits”.
         - MemberExpr pointing to something named “work” accessing “data” via “->data” or “.data”.
       - Ensure no access-qualifiers are used that make the read safe:
         - Reject if Init contains “READ_ONCE”, “ACCESS_ONCE”, “smp_load_acquire”. Use ExprHasName to screen these.
  2) BinaryOperator assignment ‘=’ writing to that same variable:
     - LHS is a DeclRefExpr to a VarDecl (often named “data” but verify by actual usage in the If condition).
     - RHS satisfies the same “unsafe read” criteria as in (1).
     - Ensure RHS also does not contain READ_ONCE/ACCESS_ONCE/smp_load_acquire.
- If neither form is found immediately preceding the IfStmt, do not report (this ensures we only warn when the read happens unconditionally before the guard condition).

Step C: Additional filters to limit false positives (simple and targeted)
- Ensure the guard operand name contains “from_cancel” to match the intended kernel pattern. If needed, allow “from_cancel” to appear in a compound expression, but it must be in the leftmost && operand.
- When scanning RHS for “->data”, also ensure the base object name likely matches the intended target, e.g., ExprHasName(RHS, "work") && ExprHasName(RHS, "->data"). This ties the read to work->data and reduces noise.
- If the RHS contains any of “READ_ONCE”, “ACCESS_ONCE”, “smp_load_acquire”, or other clearly safe accessors, do not report.

Step D: Reporting
- Location to report: Prefer reporting at the read site (the RHS of the DeclStmt initializer or RHS of the assignment) because that is the speculative/early read. If extracting a precise subrange is complex, report on the preceding statement as a whole.
- Generate a non-fatal error node via C.generateNonFatalErrorNode().
- Emit a PathSensitiveBugReport with a short message:
  - “Early read of work->data before checking from_cancel; may race with concurrent writers.”
- Optionally, add a note that suggests the safe pattern:
  - “Check from_cancel first, then read work->data (or use READ_ONCE).”
- Use a dedicated BugType, e.g., “Speculative read before guard”.

4) Helper logic to include in the checker
- Flattening helper for logical-and:
  - Given an Expr for the condition, peel off nested BO_LAnd to produce an ordered vector: [leftmost, ..., rightmost].
- Previous-sibling finder:
  - Given an IfStmt and its parent CompoundStmt, iterate the body stmts to find the IfStmt index and return the previous non-empty statement.
- Condition-use check:
  - To confirm that the variable assigned in the preceding stmt is actually used in the If condition, scan If condition for DeclRefExprs and match the VarDecl pointer identity.

5) Summary of the minimal, concrete detection rule
- Pattern to flag:
  - In a function where an If condition starts with a “from_cancel” check (as the leftmost && operand),
  - The statement immediately preceding that If performs an unconditional read of work->data (directly or via *work_data_bits(work)) into a local,
  - Without READ_ONCE/ACCESS_ONCE-like qualifiers,
  - And that local (or the read result) is used in the non-leftmost part(s) of the If condition.
- Report: “Early read of work->data before checking from_cancel; may race with concurrent writers.”
