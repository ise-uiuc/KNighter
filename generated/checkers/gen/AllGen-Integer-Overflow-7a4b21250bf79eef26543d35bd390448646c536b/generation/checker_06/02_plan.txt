Plan to detect unsafe zero-check of roundup_pow_of_two() results (32-bit UB)

1. Program state
- REGISTER_SET_WITH_PROGRAMSTATE(RoundupSyms, SymbolRef)
  - Stores the symbolic return values produced by calls to roundup_pow_of_two().
  - No alias maps are needed; the symbol flows with the value and will be read back at the use site.

2. Callbacks and their roles
- checkPostCall
  - Goal: Record the symbolic result of roundup_pow_of_two().
  - Steps:
    1. Identify function by name:
       - If Call.getCalleeIdentifier() exists and its name equals "roundup_pow_of_two", proceed.
    2. Get the return value:
       - SVal Ret = Call.getReturnValue(); if it’s a DefinedSVal and has a SymbolRef (Ret.getAsSymbol()), add it to RoundupSyms.
    3. Update state with State->add<RoundupSyms>(Sym) and C.addTransition(State).
  - Notes:
    - This works both when the call’s result is assigned to a variable and when it’s used directly in conditions; the return value symbol will be propagated by the analyzer.

- checkBranchCondition
  - Goal: Detect zero-checks on roundup_pow_of_two() results, which imply relying on overflow turning into zero.
  - Patterns to detect:
    1. Unary logical-not:
       - if (!X)
    2. Explicit comparison against zero:
       - if (X == 0) or if (0 == X)
  - Steps:
    1. Normalize the condition expression: const Expr *CondE = dyn_cast<Expr>(Condition)->IgnoreParenImpCasts().
    2. Handle logical-not:
       - If CondE is a UnaryOperator with opcode UO_LNot, let X = SubExpr->IgnoreParenImpCasts().
       - Obtain SVal SV = C.getSVal(X). If SV.getAsSymbol() exists and is in RoundupSyms, report a bug.
       - If there is no symbol match, also try to detect direct call: if X (or a child) is a CallExpr whose callee is named "roundup_pow_of_two", report a bug.
    3. Handle equality to zero:
       - If CondE is a BinaryOperator with opcode BO_EQ (we focus on == 0 checks; != 0 is not the problematic overflow-as-zero check):
         - Let L = LHS->IgnoreParenImpCasts(), R = RHS->IgnoreParenImpCasts().
         - Evaluate either side to an integer using EvaluateExprToInt. If one side is constant zero:
           - For the non-zero side N, obtain SVal NSV = C.getSVal(N). If NSV.getAsSymbol() is in RoundupSyms, report a bug.
           - If symbol not found, also check if N (or one of its children) is a CallExpr to "roundup_pow_of_two" and report if so.
    4. Emitting the report:
       - Generate a non-fatal error node with C.generateNonFatalErrorNode().
       - If node is null, return.
       - Create a PathSensitiveBugReport with a short message, e.g.:
         - "Do not zero-check roundup_pow_of_two() result; overflow is UB on 32-bit. Pre-check arg (> 1UL << 31) before calling."
       - Attach the condition’s source range to the report and emit.
  - Notes:
    - We intentionally do not require proving the argument range or architecture; this is a pattern-based diagnostic aligned with the kernel fix.
    - We only warn for BO_EQ-to-zero or logical-not. These are the canonical “overflow -> zero” checks used in the buggy pattern.

3. Optional helper logic inside checkBranchCondition
- Detecting direct calls in the condition:
  - Use findSpecificTypeInChildren<CallExpr>(Expr) to find a CallExpr under the relevant sub-expression.
  - If found, verify the callee name equals "roundup_pow_of_two".
- Checking constants:
  - Use EvaluateExprToInt(EvalRes, Expr, C) to robustly detect literal zero across casts/macros.

4. What we do not track (to keep it simple)
- No alias maps: the symbolic value from the call naturally flows into variables and through assignments; reading those variables yields the same symbol.
- No attempt to suppress warnings if a correct pre-check (arg > 1UL << 31) is present; keeping the checker simple avoids complex control-flow mining and reduces brittleness.

5. Summary of minimal implementation steps
- Define RoundupSyms as a program state set of SymbolRef.
- In checkPostCall:
  - If callee name is "roundup_pow_of_two", grab return SymbolRef and add to RoundupSyms.
- In checkBranchCondition:
  - If condition is (!X) or (X == 0) or (0 == X):
    - Check whether X’s symbol is in RoundupSyms.
    - Or whether X directly calls "roundup_pow_of_two".
    - If yes, report with a short message.
