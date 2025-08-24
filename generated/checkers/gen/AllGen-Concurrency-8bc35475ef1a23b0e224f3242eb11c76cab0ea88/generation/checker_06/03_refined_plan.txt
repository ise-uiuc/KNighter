Plan

1) Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(SpeculativeLoadMap, const VarRegion *, const Stmt *)
  - Key: the local variable that receives the value read from shared memory (e.g., data).
  - Value: the Stmt pointer of the assignment/initialization that performed the read.
- Rationale: We only need to remember that a specific local variable was filled by a suspicious dereference (potentially reading a concurrently modified location) right before a guard-checking if-statement.

2) Callbacks and logic
- checkPostStmt(const DeclStmt *DS, CheckerContext &C)
  - Goal: Capture “T x = *call(...);” initializations.
  - For each VarDecl in DS:
    - If it has an initializer, let Init = VD->getInit().
    - Run analyzeAssignment(VD, Init, DS, C).
  - If analyzeAssignment returns true, insert into SpeculativeLoadMap: (VarRegion of VD) -> DS.

- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
  - Goal: Capture “x = *call(...);” assignments.
  - If S is a BinaryOperator and isAssignmentOp():
    - Extract LHS and RHS Exprs.
    - Get VD from LHS if LHS is a DeclRefExpr to a VarDecl with local storage. Ignore non-local or non-scalar.
    - Run analyzeAssignment(VD, RHS, S, C).
  - If analyzeAssignment returns true, insert into SpeculativeLoadMap: (VarRegion of VD) -> S.

- checkBranchCondition(const Stmt *Condition, CheckerContext &C)
  - Goal: Detect the pattern “if (Guard && ... uses X ...)” where X was read speculatively just before this if.
  - Find the IfStmt ancestor with findSpecificTypeInParents<IfStmt>(Condition, C). If none, return.
  - Let IfS = that IfStmt and CondExpr = IfS->getCond().
  - Only handle top-level logical AND: if CondExpr is a BinaryOperator with opcode BO_LAnd:
    - Let LHS = CondExpr->getLHS(), RHS = CondExpr->getRHS().
    - For each (VarRegion* VR -> Stmt* LoadS) pair in SpeculativeLoadMap:
      - Obtain the VarDecl* VD for VR and its name N.
      - Require that:
        - ExprHasName(RHS, N, C) is true (X appears in RHS),
        - ExprHasName(LHS, N, C) is false (X not referenced in the guard),
        - The IfStmt is immediately after the speculative load statement:
          - Use findSpecificTypeInParents<CompoundStmt>(IfS, C) to get the enclosing block.
          - Iterate block’s children to find IfS index i and check i > 0 and block[i-1] == LoadS.
      - If all hold, report a bug at LoadS:
        - Message: “Unguarded read before guard; move the read under the ‘if (guard)’.”
        - Build a PathSensitiveBugReport or BasicBugReport, anchor at LoadS (the dereference) and optionally add a note at IfS.
      - After reporting (or when the condition is handled), erase VR from SpeculativeLoadMap to avoid duplicates on the same path.

- checkEndFunction(const ReturnStmt *RS, CheckerContext &C)
  - Clear SpeculativeLoadMap.

3) Helper: analyzeAssignment
- Signature: bool analyzeAssignment(const VarDecl *VD, const Expr *RHS, const Stmt *BindSite, CheckerContext &C)
- Purpose: Decide whether RHS looks like a speculative read of shared state that should be guarded but is not yet guarded.
- Steps:
  - Preconditions on destination:
    - VD must be a local variable (automatic storage) of integral or pointer type.
  - Recognize a suspicious memory read shape on RHS:
    - Preferred canonical pattern: dereference of a function call result:
      - Find a UnaryOperator U with opcode UO_Deref within RHS using findSpecificTypeInChildren<UnaryOperator>(RHS).
      - Confirm U’s subexpression is a CallExpr CE. If not, return false.
      - Optional macro guard: if ExprHasName(RHS, "READ_ONCE", C) or ExprHasName(RHS, "atomic", C), return false (assumed intentional synchronization).
    - Additionally, filter to likely-shared source:
      - If CE has at least one argument A0, try to classify A0’s region:
        - const MemRegion* R = getMemRegionFromExpr(A0, C).
        - Accept if R is a ParamRegion (argument of the current function) or a VarRegion whose VarDecl has global storage (VD->hasGlobalStorage()). If unknown, be conservative and return false to limit false positives.
  - If all checks pass, return true to indicate the assignment is a candidate speculative read to be paired with a subsequent if(guard && uses(X)).

4) Why this detects the target pattern
- The checker records when a local variable is computed from a dereference of a pointer returned by a call tied to a parameter/global (likely shared) and the expression is not obviously guarded (i.e., not READ_ONCE()).
- Immediately afterward, if the next statement is an if with top-level “Guard && …” and the right-hand side references that just-read local variable, it means the read happened before the guard that makes the read safe. Even though the variable may not be used if Guard is false, the early read can race (as in the patch).
- Requiring adjacency (assignment directly followed by the if) and the RHS referencing the variable minimizes false positives and matches the kernel change.

5) Reporting
- Use generateNonFatalErrorNode and emit via a PathSensitiveBugReport (or BasicBugReport).
- Short message: “Speculative unguarded read; move the read under the guard.”
- Primary location: the dereference assignment statement. Optionally add a note pointing to the IfStmt condition to highlight the guard.

6) Notes and limitations (intentional for simplicity and precision)
- Only flags the canonical pattern “X = *call(...); if (Guard && uses X) …” with adjacency in the same compound block.
- Requires RHS dereference of a CallExpr and the call argument to refer to a function parameter or a global (heuristic for shared state).
- Skips cases using READ_ONCE/atomic-like markers.
- Clears state at function end; state is path-sensitive by design.
