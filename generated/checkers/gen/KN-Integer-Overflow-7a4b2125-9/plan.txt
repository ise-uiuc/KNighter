Plan: Detect unsafe overflow check relying on roundup_pow_of_two() result being 0 on 32-bit arches

1. Program State
- Use one map to remember which variables hold the result of roundup_pow_of_two():
  - REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResMap, const MemRegion*, const Expr*)
  - Key: the LHS MemRegion being assigned.
  - Value: the original input expression passed to roundup_pow_of_two() (for diagnostics).
- No alias or taint tracking: keep it simple and focus on direct assignments and direct calls in conditions.

2. Callbacks and Logic

2.1 checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
- Goal: Track when a variable is assigned the result of roundup_pow_of_two(x).
- Steps:
  - Get the destination MemRegion: const MemRegion *R = Loc.getAsRegion(); if null, return.
  - Find a CallExpr in S using findSpecificTypeInChildren<CallExpr>(S). If none, this is a normal bind:
    - Remove any prior tracking for R: State = State->remove<RoundupResMap>(R); C.addTransition(State).
    - Return.
  - If there is a CallExpr, check if its callee identifier name equals "roundup_pow_of_two" (use callee IdentifierInfo or fallback to ExprHasName on the textual callee if needed).
  - If callee matches:
    - Extract the argument expression ArgE = CE->getArg(0)->IgnoreImpCasts().
    - State = State->set<RoundupResMap>(R, ArgE); C.addTransition(State).
  - Else (other call assigned):
    - State = State->remove<RoundupResMap>(R); C.addTransition(State).

2.2 checkBranchCondition(const Stmt *Condition, CheckerContext &C)
- Goal: Flag conditions that test the result of roundup_pow_of_two() for zero to detect overflow.
- Only run on 32-bit unsigned long targets to avoid false positives:
  - if (C.getASTContext().getTypeSize(C.getASTContext().LongTy) != 32) return;
- Extract the “zero-tested” subexpression X from the condition:
  - Let CondE = dyn_cast<Expr>(Condition)->IgnoreImpCasts().
  - Pattern A (logical not): if (const auto *U = dyn_cast<UnaryOperator>(CondE)) and U->getOpcode() == UO_LNot:
    - X = U->getSubExpr()->IgnoreImpCasts().
  - Pattern B (binary == 0): if (const auto *B = dyn_cast<BinaryOperator>(CondE)) and B->getOpcode() == BO_EQ:
    - If RHS is integer constant 0 (use EvaluateExprToInt on B->getRHS() and check equals 0), set X = B->getLHS()->IgnoreImpCasts().
    - Else if LHS is integer constant 0, set X = B->getRHS()->IgnoreImpCasts().
  - If neither pattern matches, return.
- Determine if X is derived from roundup_pow_of_two():
  - Case 1: X is a direct call: if (const CallExpr *CE = dyn_cast<CallExpr>(X)) and its callee name is "roundup_pow_of_two": report.
  - Case 2: X is a variable/expression with a MemRegion:
    - const MemRegion *R = getMemRegionFromExpr(X, C).
    - If R is null, return.
    - Look up RoundupResMap[R]. If it exists, report.
- Emit bug:
  - Create a non-fatal error node. If null, return.
  - Use a PathSensitiveBugReport with a short message, e.g.:
    - "Do not use roundup_pow_of_two(x) == 0 to detect overflow on 32-bit; left shift may be undefined. Pre-check x > 1UL << 31 before rounding."
  - Add range: Condition->getSourceRange().
  - Optionally add a note pointing to the assignment or call site (if RoundupResMap provided ArgE or if X was a CallExpr).

3. Helper Checks and Utilities
- isRoundupPow2Call(const CallExpr *CE, CheckerContext &C):
  - Return true if CE has callee IdentifierInfo and name equals "roundup_pow_of_two".
  - If IdentifierInfo is not available (macro), optionally fallback using ExprHasName on the callee expression.
- extractZeroTestedExpr(Expr *CondE): Implement logic from 2.2 to return X or nullptr.
- is32BitULong(CheckerContext &C): getTypeSize(LongTy) == 32.
- Use provided utilities:
  - findSpecificTypeInChildren to detect the CallExpr in checkBind.
  - EvaluateExprToInt to check for 0 in equality comparisons.
  - getMemRegionFromExpr to map expressions to regions for RoundupResMap.

4. Reporting
- BugType: One BugType instance, e.g., "Unsafe overflow check after roundup_pow_of_two".
- Report message (short and clear):
  - "roundup_pow_of_two() overflow cannot be detected via == 0 on 32-bit; pre-check the input before rounding."

5. Notes and Scope
- This checker warns only on 32-bit unsigned long targets to match the UB scenario.
- It detects both:
  - Direct condition: if (!roundup_pow_of_two(x)) / if (roundup_pow_of_two(x) == 0)
  - Indirect via variable: n = roundup_pow_of_two(x); if (!n) ...
- On any re-assignment to a tracked variable, the map entry is removed to avoid stale tracking.
