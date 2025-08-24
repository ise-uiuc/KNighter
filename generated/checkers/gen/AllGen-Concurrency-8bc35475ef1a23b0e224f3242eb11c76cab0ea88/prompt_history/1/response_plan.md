Plan

1) Program state
- No custom program state is necessary. This checker is primarily a local AST/pattern check around if-conditions and immediately preceding statements.

2) Callbacks
- Use only checkBranchCondition to hook every if-condition and analyze the surrounding AST context. This keeps the checker simple and focused on the pattern.

3) Detection logic in checkBranchCondition
- Goal: Flag an unconditional read of a shared field/state that happens right before an if-condition that gates access (via a guard on the left side of &&), when the read value is consumed in the condition or guarded block.

Step-by-step:
a) Filter to If conditions with logical-and:
   - From the callback input Stmt* Condition, find a BinaryOperator with operator &&.
     - Use findSpecificTypeInChildren<BinaryOperator>(Condition) and ensure it is a logical-and (Opcode == BO_LAnd).
     - Support nested && by recursively flattening or by focusing on the top-level left-right split (it is sufficient to analyze the leftmost LHS and the immediate RHS for the primary pattern).
b) Identify the guard:
   - Extract LHS of the top-level LogicalAnd (LHS).
   - Heuristic filter to reduce false positives:
     - Prefer LHS that references a boolean guard-ish variable (DeclRefExpr of bool/Bit type).
     - Optionally use ExprHasName on LHS or entire Condition to prefer variables with names like "from", "cancel" (e.g., ExprHasName(LHS, "from") or ExprHasName(Condition, "cancel")).
     - If this heuristic is too restrictive, fall back to any LHS that is a non-constant expression.
c) Identify RHS variables used in the condition:
   - Collect DeclRefExprs in the RHS (right-hand of &&).
   - Focus on identifiers used as rvalues in RHS (e.g., “data” in (data & CONST)).
   - Record the VarDecl* for each candidate variable V that appears on RHS.
d) Locate the statement immediately preceding the IfStmt:
   - Climb to the enclosing IfStmt with findSpecificTypeInParents<IfStmt>(Condition, C).
   - Then climb to the parent CompoundStmt with findSpecificTypeInParents<CompoundStmt>(IfStmt, C).
   - Iterate CompoundStmt’s body to find the index of the IfStmt; if there is a previous sibling statement PrevS, analyze it. If not, return.
e) Check if PrevS computes/reads the RHS variable(s) from a shared/concurrently-updated field:
   - Handle these patterns:
     1) Assignment statement:
        - PrevS is a BinaryOperator with opcode BO_Assign.
        - LHS is a DeclRefExpr to one of the RHS variables V seen in step (c).
        - RHS is a “raw memory read” expression (see criteria below).
     2) Decl with init:
        - PrevS is a DeclStmt with a single VarDecl VD where VD == V and VD has an initializer.
        - Init is a “raw memory read” expression.
   - Raw memory read criteria (any one true):
     - RHS is UnaryOperator UO_Deref (e.g., *expr).
     - RHS is a MemberExpr with isArrow() (e.g., ptr->field).
     - RHS is ArraySubscriptExpr where the base is a pointer-like expression.
     - RHS is UnaryOperator UO_Deref of a CallExpr whose callee name contains “data” (e.g., work_data_bits). Use ExprHasName(RHS, "data") or check the CallExpr callee identifier.
     - RHS contains a MemberExpr accessing a field with name “data” (use ExprHasName(RHS, "->data") or ExprHasName(RHS, ".data")).
   - Additional heuristics to reduce false positives:
     - If RHS source contains “READ_ONCE” (ExprHasName(RHS, "READ_ONCE")), skip (already using atomic accessor).
     - If RHS base expression references a function parameter or a global (likely shared), prefer reporting; for MemberExpr, check base is DeclRefExpr to ParmVarDecl or global VarDecl.
f) Confirm the suspicious pattern:
   - We have: previous statement performs a raw memory read into a local variable V; the if-condition is of the form (Guard && RHS_using_V).
   - This implies the non-atomic read of shared state happens unconditionally before the guard that supposedly establishes safety/ownership.
g) Emit a report:
   - Use C.generateNonFatalErrorNode(); if null, return.
   - Create a PathSensitiveBugReport with a short message:
     - “Unconditional read of shared state before guard; move the read under the guard to avoid races.”
   - Highlight the read expression range (the RHS of the assignment/init).
   - Optionally add a note range for the guard expression (LHS of &&).

4) Utility functions usage
- findSpecificTypeInParents:
  - To find the surrounding IfStmt and then the parent CompoundStmt.
- findSpecificTypeInChildren:
  - To find BinaryOperator ‘&&’ inside the condition.
- ExprHasName:
  - To heuristically detect names like "data", "->data", ".data", "READ_ONCE", “work_data_bits”, or guard-ish cues like “from”/“cancel”.

5) Edge cases and de-duplication
- Only analyze the immediate previous sibling statement. This keeps the checker simple and reduces FPs; it matches the common “compute then if (guard && use)” layout.
- Skip if the RHS variable V is also assigned in the same If condition (rare) or if LHS of && references V (avoid weird self-guarded patterns).
- Skip if the previous read is clearly atomic (READ_ONCE present).
- No state storage is required; each If condition is analyzed once when seen.

6) Summary of the minimal algorithm
- On each if-condition:
  - If it is “A && B”, collect variables in B.
  - Look at the immediate previous statement; if it assigns/initializes one of those variables using a raw memory read (pointer deref/member access) without atomic macro, warn.
- This directly captures the kernel pattern: data = *work_data_bits(work); if (from_cancel && (data & ...)) … and suggests moving the data read inside the guard.
