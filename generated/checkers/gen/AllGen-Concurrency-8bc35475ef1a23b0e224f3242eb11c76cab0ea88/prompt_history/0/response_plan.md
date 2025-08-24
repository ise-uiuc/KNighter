1) Program state
- Do not customize program states. This checker can be purely AST- and path-structure based, using only the current CFG/AST to recognize the pattern. No REGISTER_MAP_WITH_PROGRAMSTATE is needed.

2) Callbacks to use
- checkBranchCondition: the single main callback. We analyze each if-condition to detect the “early/speculative read before guard” shape and report.

3) Detailed steps and implementation

A. Core idea to match
- We want to detect when a value is read from a potentially-shared/concurrently-modified memory location unconditionally before an if, but is only needed under a guard inside that if.
- We will implement two common shapes:
  1) AND-condition shape:
     - Pattern: decl/assign immediately before if, followed by if (Guard && Uses(VarReadFromShared) && ...).
     - Fix is to move the read into the guarded branch after Guard is true.
  2) Guard-then shape:
     - Pattern: decl/assign immediately before if, followed by if (Guard) { Uses(VarReadFromShared) ... } else { ... } where the Var is not used in the else path.
     - Fix is to move the read into the then-branch.

B. Utility helpers to implement
- Parse helpers:
  - findSpecificTypeInParents<IfStmt>(Condition, C): get the IfStmt for the given condition expression.
  - Write a small function getParentCompoundAndPrevStmt(const IfStmt *IS, const CheckerContext &C, const CompoundStmt *&CS, const Stmt *&Prev):
    - Use findSpecificTypeInParents<CompoundStmt>(IS, C).
    - Iterate CS->body() to locate IS and find its immediate previous sibling statement Prev (nullptr if none).
- Variable-use helpers:
  - const VarDecl *getAssignedVar(const Stmt *S, const Expr *&InitOrRHS):
    - If S is a DeclStmt with a single VarDecl having an initializer, return that VarDecl and set InitOrRHS to the initializer.
    - If S is a BinaryOperator (BO_Assign) with LHS DeclRefExpr to a VarDecl, return that VarDecl and set InitOrRHS to RHS.
    - Otherwise return nullptr.
  - bool stmtContainsUseOfVar(const Stmt *S, const VarDecl *VD):
    - Recursively traverse S to find any DeclRefExpr referring to VD.
  - void collectConjuncts(const Expr *Cond, SmallVector<const Expr*, 4> &Conj):
    - Decompose a left-associative chain of BO_LAnd into a vector from left to right. For non-BO_LAnd, push the Cond as a single element.
  - bool exprContainsUseOfVar(const Expr *E, const VarDecl *VD):
    - Similar traversal to stmtContainsUseOfVar.
- Racy-read classification helper:
  - bool isPotentialRacyRead(const Expr *E, CheckerContext &C):
    - Return true if any of the following holds anywhere in E (walk recursively):
      - A UnaryOperator with opcode UO_Deref (explicit dereference).
      - An ArraySubscriptExpr.
      - A MemberExpr where isArrow() is true (pointer member access) or which textually contains “->” as a heuristic.
      - Additionally, allow textual heuristics via ExprHasName(E, "work_data_bits", C) or ExprHasName(E, "->data", C) to capture common kernel patterns. This targets the given bug and similar drivers/kernel code.
    - This remains a conservative heuristic to capture “reads likely from shared/concurrently modified memory”.

C. Detection in checkBranchCondition
- Input: const Stmt *Condition, CheckerContext &C.
- Steps:
  1) Find the IfStmt:
     - const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C).
     - If null, return.
  2) Find the immediate previous statement in the same block:
     - const CompoundStmt *CS; const Stmt *Prev;
     - getParentCompoundAndPrevStmt(IS, C, CS, Prev);
     - If Prev is null, return.
  3) Try to extract a variable assignment that happens in Prev:
     - const Expr *InitOrRHS = nullptr;
     - const VarDecl *VD = getAssignedVar(Prev, InitOrRHS);
     - If VD == nullptr or InitOrRHS == nullptr, return.
     - If !isPotentialRacyRead(InitOrRHS, C), return. We require the previous assignment to look like a load/deref/member/array read that could be shared.
  4) Identify the two shapes:

     Shape 1: AND-condition shape
     - Decompose the condition into conjuncts using collectConjuncts.
     - If there are at least 2 conjuncts:
       - Let Guard = conjuncts[0].
       - Check that Guard does not reference VD: !exprContainsUseOfVar(Guard, VD).
       - Check that at least one of the remaining conjuncts references VD.
       - If satisfied, we have the pattern “V = read; if (Guard && uses(V)) ...”.
       - Emit a report.

     Shape 2: Guard-then shape
     - If the condition does not match the AND-condition shape, or even if it does but you also want to catch more, check:
       - Let ThenS = IS->getThen(); Let ElseS = IS->getElse();
       - If exprContainsUseOfVar(cast<Expr>(Condition), VD) is true, skip this shape (we only handle pure if (Guard) {...} here).
       - If stmtContainsUseOfVar(ThenS, VD) is true AND (ElseS is null OR stmtContainsUseOfVar(ElseS, VD) is false):
         - We have “V = read; if (Guard) { uses(V) } [else doesn’t use V]”.
         - Emit a report.

  5) Bug report:
     - Create a BugType once, e.g., “Speculative shared read before guard”.
     - Use generateNonFatalErrorNode(C.getState()) to create a node; if null, return.
     - Create PathSensitiveBugReport with a short message:
       - “Speculative read of shared state before guard; move the read inside the guarded branch.”
     - Point the report location at the previous assignment statement (Prev) or at InitOrRHS’s source range for a precise highlight.
     - Emit with C.emitReport(...).

D. Notes and heuristics tuning
- The isPotentialRacyRead test is deliberately heuristic, but tailored to the kernel pattern illustrated:
  - Unary '*' of a call (e.g., *work_data_bits(work)).
  - Member access via '->' or array indexing before a guard.
  - Use ExprHasName for known helpers like “work_data_bits” or “->data” to reduce false positives in kernel code.
- To reduce noise:
  - Require the immediate previous statement be the read-producing assignment/decl-init.
  - Require the assigned variable to be referenced only in guarded position(s) as described.
  - Ensure the leftmost guard conjunct does not use the variable (so moving the read under the guard is feasible).

E. Optional extensions (if needed later)
- Extend the textual heuristics table for more kernel helpers or struct fields known to be concurrently updated.
- Add a quick check that the guard identifier name looks like a guard (e.g., “from_”, “is_”, “has_”, “safe_”) using ExprHasName on the leftmost conjunct; keep off by default.
- Consider also detecting patterns where the read is used only within a loop or a nested if inside the then-branch; this can be done by reusing stmtContainsUseOfVar on nested constructs.

Summary
- No program state.
- One main callback: checkBranchCondition.
- Find the IfStmt and its previous sibling statement in the same CompoundStmt.
- If the previous statement initializes/assigns a variable from a potential shared read, and that variable is only used in a guarded position (AND-condition right conjuncts or inside then-only), warn to move the read into the guarded branch.
