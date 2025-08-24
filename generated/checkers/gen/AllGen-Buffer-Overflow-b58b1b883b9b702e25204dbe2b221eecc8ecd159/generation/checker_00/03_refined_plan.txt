Plan

1. Program state
- REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousVars, const MemRegion*)
  - Tracks variables that were computed as (available_len - round_up(...)) in an unsigned type, i.e., they may have wrapped due to underflow.
- REGISTER_SET_WITH_PROGRAMSTATE(GuardedVars, const MemRegion*)
  - Tracks suspicious variables that have an explicit guard seen in a branch condition (e.g., if (shorten >= len) …), so subtracting them is likely safe.
- No other custom traits/maps are necessary.

2. Helper predicates/utilities (local static functions in the checker)
- bool isUnsignedType(QualType T)
  - Return T->isUnsignedIntegerType().
- bool isRoundUpLike(const Expr *E, CheckerContext &C)
  - Return true if the source text of E contains any of: "round_up", "roundup", "ALIGN", "ALIGN_UP". Use ExprHasName(E, ..., C).
  - Additionally: if E is a CallExpr, and callee name is one of the above, return true.
- bool isSuspiciousMinus(const Expr *E, CheckerContext &C)
  - Return true if E is a BinaryOperator with opcode BO_Sub, LHS is any expr, RHS satisfies isRoundUpLike(RHS, C).
- const MemRegion *getRegionIfVarOrField(const Expr *E, CheckerContext &C)
  - Use getMemRegionFromExpr(E, C) and return the base region when E is a DeclRefExpr or a field/member that maps to a region.
- bool isZeroExpr(const Expr *E)
  - Check if E is an integer literal equal to 0 (ignoring implicit casts), or EvaluateExprToInt succeeds and equals 0.
- bool isSubAssignOnUnsigned(const BinaryOperator *BO)
  - BO->getOpcode() == BO_SubAssign and LHS type is unsigned integer.
- bool isAssignWithMinusOnUnsigned(const BinaryOperator *BO)
  - BO->isAssignmentOp() and BO->getOpcode() == BO_Assign, RHS is BO_Sub, and LHS type is unsigned integer.
- bool guardConditionMentionsVarGEorGT(const Expr *Cond, const MemRegion *VarR, CheckerContext &C)
  - If Cond is a BinaryOperator with opcode BO_GE or BO_GT:
    - If either side’s expression region equals VarR (via getRegionIfVarOrField), return true.
  - Else recursively check children (or use findSpecificTypeInChildren<BinaryOperator>()) and test all BinaryOperators in the condition.
- bool immediateIfGuardSetsVarZero(const Stmt *S, const MemRegion *VarR, CheckerContext &C)
  - If the parent of S (findSpecificTypeInParents<CompoundStmt>()) is a CompoundStmt, scan the preceding sibling statement:
    - If it is an IfStmt:
      - If the condition guardConditionMentionsVarGEorGT on VarR is true, and inside the Then branch, there exists a BinaryOperator assignment setting VarR to zero (use findSpecificTypeInChildren<BinaryOperator>() on then body and check isZeroExpr on RHS and LHS region equals VarR), return true.
  - This is an optional local-guard heuristic to reduce false positives for direct “Y -= (A - round_up(...))” patterns.

3. checkPostStmt(const DeclStmt *DS, CheckerContext &C)
- Goal: detect initialization like size_t shorten = avail - round_up(...);
- For each VarDecl in DS with an initializer:
  - If the declared type is unsigned integer, and the initializer isSuspiciousMinus(Init, C):
    - Get the MemRegion of the declared variable via getMemRegionFromExpr(DeclRefExpr(...), C) or from State binding of the VarDecl; insert into SuspiciousVars.
- No bug report here; only record suspicious origin.

4. checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
- Handle assignments and compound assignments in one place.

A) Mark suspicious variable when assigned a suspicious-minus expression
- If S is a BinaryOperator BO with opcode BO_Assign:
  - Let LHS be the assigned-to expr; if LHS type is unsigned integer:
    - If RHS isSuspiciousMinus(RHS, C), then:
      - Get region of LHS via getRegionIfVarOrField(LHS, C).
      - Add region to SuspiciousVars.
      - Remove region from GuardedVars (fresh computation invalidates prior guards).
    - Else if RHS isZeroExpr(RHS) and LHS region is in SuspiciousVars:
      - Remove LHS region from SuspiciousVars (explicit zeroing makes further subtracts safe).
      - Also remove from GuardedVars.

B) Detect dangerous subtract: Y -= X
- If S is a BinaryOperator BO with opcode BO_SubAssign and LHS is unsigned:
  - Case B1: RHS is a DeclRefExpr (or region-backed expr):
    - Get RHS region R via getRegionIfVarOrField(RHS, C).
    - If R is in SuspiciousVars:
      - If R is in GuardedVars, do nothing (assume guarded in this path).
      - Else if immediateIfGuardSetsVarZero(S, R, C) is true, do nothing.
      - Else: report bug at this statement.
  - Case B2: RHS is not a simple var: If RHS isSuspiciousMinus(RHS, C), then:
    - If immediateIfGuardSetsVarZero(S, /*VarR*/nullptr, C) is false (cannot tie to a var), report bug at this statement.

C) Detect dangerous subtract: Y = Y - X
- If S is a BinaryOperator BO with opcode BO_Assign and LHS is unsigned:
  - If RHS is a BinaryOperator with opcode BO_Sub:
    - Let RHS_R be RHS->getRHS():
      - If RHS_R is a DeclRefExpr with region R in SuspiciousVars:
        - If R in GuardedVars -> skip; else if immediateIfGuardSetsVarZero(S, R, C) -> skip; else report.
      - Else if RHS_R isSuspiciousMinus(RHS_R, C):
        - If immediateIfGuardSetsVarZero(S, nullptr, C) is false -> report.

D) Reset guards on reassignment
- If BO is an assignment to a variable region R that is in SuspiciousVars but RHS is neither zero nor suspicious-minus, remove R from GuardedVars (any new value invalidates the old guard).

5. checkBranchCondition(const Stmt *Condition, CheckerContext &C)
- Purpose: recognize guards like if (shorten >= len) ... in the current path.
- For each region R in SuspiciousVars (iterate via ProgramState’s set):
  - If guardConditionMentionsVarGEorGT(cast<Expr>(Condition), R, C) is true:
    - Add R to GuardedVars in the returned ProgramState.
- This marks the path as having seen a relevant guard. It will be consumed implicitly by the later subtract detection.
- Note: If the suspicious variable is reassigned later (checkBind), we remove it from GuardedVars.

6. Bug reporting
- When reporting in step 4B/4C, create a PathSensitiveBugReport:
  - BugType: "Possible size_t underflow"
  - Message: "Subtracting (avail - round_up(...)) from length without bound check may underflow"
  - Use generateNonFatalErrorNode() to get a node; if null, return.
  - Add the range of the subtraction statement (the BO) to the report.
- Do not report more than once on the same statement. You can keep a small in-checker hash set of reported statements if needed (not part of ProgramState).

7. Notes and simplifications
- This checker focuses on the round-up family: round_up, roundup, ALIGN, ALIGN_UP; add more names if needed by extending isRoundUpLike.
- The core risk is unsigned underflow in computing X = A - round_up(...), which then propagates via Y -= X. The checker either:
  - sees Y -= (A - round_up(...)) directly, or
  - tracks a variable X computed in that form and later subtracted.
- Guards:
  - Path guard (checkBranchCondition): marks a variable as guarded upon seeing if (X >= Y) ... (>= or >).
  - Local heuristic guard (immediateIfGuardSetsVarZero): detects the common pattern "if (X >= Y) X = 0;" immediately before the subtraction.
- The checker intentionally does not try to prove round_up(...) <= avail via symbolic reasoning; it uses pattern-based recognition as in the target patch.

8. Chosen callbacks summary
- checkPostStmt(const DeclStmt *):
  - Record suspicious variable at initialization.
- checkBind(SVal, SVal, const Stmt *):
  - Record suspicious variable at assignment.
  - Detect subtract patterns (Y -= X and Y = Y - X) and emit reports if unguarded.
  - Maintain GuardedVars on reassignment/zeroing.
- checkBranchCondition(const Stmt *):
  - Mark suspicious variables as guarded when branch conditions compare them (>= or >) to another value.

This plan is minimal, path-sensitive where it matters, leverages name-based round-up detection to match kernel macros, and mirrors the fix pattern (if (shorten >= len) shorten = 0) to suppress false positives.
