1) Program state
- No custom program state is required for the minimal, robust version of this checker. We only need to inspect call expressions and the shape of their size argument.
- Optional refinement (not required): A lightweight “from user” taint to further reduce false positives:
  - REGISTER_SET_WITH_PROGRAMSTATE(UserTaintedRegions, const MemRegion *)
  - In checkPostCall of copy_from_user, mark the destination region as tainted.
  - In checkBind, propagate taint from RHS to LHS for simple assignments.
  - In checkPreCall (when checking the multiplication), prefer to warn only if the “count” expression resolves to a region in UserTaintedRegions or to a symbol derived from it.
  - This is an optional step, keep the core checker simple.

2) Callbacks and implementation details

A. checkPreCall
- Goal: Flag calls where a size argument is computed as sizeof(element) * count (open-coded multiplication) instead of using overflow-safe helpers like array_size() or struct_size().
- Steps:
  1) Identify target functions and the index of their size parameter:
     - copy_from_user(dst, src, n) => size index 2 (0-based).
     - copy_to_user(dst, src, n) => size index 2 (0-based).
     - (Optional: extendable list via a small table of {FunctionName, SizeParamIndex}.)
  2) If callee matches one of the above, get the size argument expression: const Expr *SizeE = Call.getArgExpr(SizeIdx).
     - Ignore implicit casts and parentheses: E = SizeE->IgnoreParenImpCasts().
     - As a quick guard, if ExprHasName(SizeE, "array_size", C) or ExprHasName(SizeE, "struct_size", C), return (already safe).
  3) Detect the open-coded multiplication:
     - If E is a BinaryOperator with opcode == BO_Mul:
       - Let L = LHS->IgnoreParenImpCasts(), R = RHS->IgnoreParenImpCasts().
       - Define helper isSizeofExpr(const Expr *X): returns true if dyn_cast<UnaryExprOrTypeTraitExpr>(X) with getKind()==UETT_SizeOf.
       - If !(isSizeofExpr(L) XOR isSizeofExpr(R)): return (we care only about exactly one side being sizeof; both sides being sizeof is unusual and not our target).
       - Let CountExpr be the non-sizeof side.
       - If EvaluateExprToInt(EvalRes, CountExpr, C) succeeds, return (constant count; very low risk of overflow).
       - (Optional refinement if you implemented taint:) If getMemRegionFromExpr(CountExpr, C) is not in UserTaintedRegions and the symbol max value can be inferred as small via inferSymbolMaxVal (e.g., maxVal <= 4096), consider skipping to reduce noise.
  4) Report:
     - Create a BugType once (e.g., "Open-coded size multiplication may overflow").
     - Generate a non-fatal error node.
     - Emit a concise message like: "Size is computed as sizeof(x) * count; use array_size() to avoid overflow."
     - Point the report to SizeE’s source range.

B. (Optional) checkPostCall (for optional taint, not required for minimal checker)
- Goal: Mark memory written by copy_from_user as “from user”.
- Steps:
  1) If the callee is copy_from_user:
     - Get the destination pointer expression (arg 0). Obtain its MemRegion via getMemRegionFromExpr().
     - Insert that MemRegion into UserTaintedRegions.

C. (Optional) checkBind (for optional taint propagation)
- Goal: Propagate “from user” taint through simple assignments that bind values to variables used later as counts.
- Steps:
  1) When binding Loc = Val:
     - If Val is an SVal associated with a region in UserTaintedRegions (or a symbol derived from one), and Loc resolves to a MemRegion, add that region into UserTaintedRegions.
     - Keep propagation simple; do not attempt deep expression tracking—just direct assignments.

3) Helper utilities to use
- EvaluateExprToInt: to skip cases where count is a compile-time constant (lower false positives).
- ExprHasName: to early-exit if the code already uses array_size() / struct_size().
- getMemRegionFromExpr: needed if you implement the optional taint refinement.
- findSpecificTypeInChildren/Parents: not required for the minimal version.

4) Notes and heuristics
- Keep the initial scope narrow: only copy_from_user and copy_to_user with size arg at index 2. This already covers the provided patch pattern.
- Multiplication shape to detect: sizeof(...) * Expr or Expr * sizeof(...).
- Skip if CountExpr is constant-evaluable.
- Do not warn if array_size() or struct_size() is already used.
- Message should be short and clear:
  - "Size is computed as sizeof(x) * count; use array_size() to avoid overflow."

5) Summary flow
- checkPreCall:
  - Match function and size arg index.
  - If size arg is a multiplication with exactly one sizeof operand and the other operand is non-constant, warn.
- Optional: Use checkPostCall and checkBind for a small taint system to reduce false positives by focusing on user-influenced counts.
