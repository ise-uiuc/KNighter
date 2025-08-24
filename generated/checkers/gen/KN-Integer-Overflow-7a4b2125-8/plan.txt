Plan

1) Program state
- Register one map to remember variables that currently hold the result of roundup_pow_of_two():
  REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResMap, const MemRegion*, const Expr*)
  where the key is the MemRegion of the LHS variable and the value is the argument expression passed to roundup_pow_of_two(). The value is optional for reporting/context; we only need to know “this var came from roundup_pow_of_two()”.

- No alias tracking and no other traits/maps (keep it simple). If the variable is reassigned later with a non-roundup value, we remove it from the map.

2) Callbacks and how to implement them

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
- Goal:
  - Detect when a variable is assigned (or initialized) from roundup_pow_of_two(...)
  - Record that LHS region in RoundupResMap.
  - Drop the record when the variable gets any other value later.

- Steps:
  1. Retrieve the destination region:
     - If Loc.getAsRegion() is null, return.
     - Let LHSReg = Loc.getAsRegion().

  2. Identify whether the bound value at this statement comes from a call to roundup_pow_of_two:
     - Use findSpecificTypeInChildren<CallExpr>(S) to locate a call expression involved in this bind.
     - If found, verify it is roundup_pow_of_two using ExprHasName(CallExprNode, "roundup_pow_of_two", C).
       - If true: extract the 0th argument expression: Arg0 = CallExprNode->getArg(0).
         - Update state: State = State->set<RoundupResMap>(LHSReg, Arg0).
         - C.addTransition(State).
         - Return.
     - If no such call is found (or the call is not roundup_pow_of_two):
       - If LHSReg exists in RoundupResMap, remove it:
         State = State->remove<RoundupResMap>(LHSReg), then C.addTransition(State).

- Rationale:
  - This catches both declarations like “u64 nb = roundup_pow_of_two(x);” and assignments “nb = roundup_pow_of_two(x);”.
  - On any subsequent non-roundup assignment to the same var, we clear the tag to avoid stale info.

B) checkBranchCondition(const Stmt *Condition, CheckerContext &C)
- Goal:
  - Report when code detects overflow by checking the result of roundup_pow_of_two() for zero.
  - Two patterns to catch:
    1) Direct-in-condition calls: if (!roundup_pow_of_two(x)) or if (roundup_pow_of_two(x) == 0)
    2) Zero-check on a variable that was previously recorded as the roundup result: if (!var) or if (var == 0) or if (0 == var)

- Steps:
  1) Direct-in-condition detection:
     - Find any CallExpr inside Condition via findSpecificTypeInChildren<CallExpr>(Condition).
     - If present and ExprHasName(CallExprNode, "roundup_pow_of_two", C) is true:
       - Determine if the condition is a zero-test:
         - Cases to accept:
           - UnaryOperator UO_LNot whose subexpr is (maybe via implicit casts) the same call.
           - BinaryOperator with op == and one side the call, the other side an integer 0 (use EvaluateExprToInt on the non-call side to confirm constant 0).
         - If matched, report (see Reporting below). Return.

  2) Variable-based detection:
     - Find a DeclRefExpr inside Condition: const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(Condition).
     - If no DRE, return.
     - Get the region for it: const MemRegion *Reg = getMemRegionFromExpr(DRE, C).
     - Lookup in RoundupResMap: if not present, return.

     - Confirm it is a zero-test on this var:
       - Pattern A: UnaryOperator UO_LNot on that var (allow embedded implicit casts).
       - Pattern B: BinaryOperator:
         - op == with one side the var (via DRE/its cast), and the other side a literal 0 (EvaluateExprToInt and check zero).
         - Also accept 0 == var (commutative).
       - (Keep it simple; skip other ops like <= for now to reduce false positives.)

     - If matched, report (see Reporting below). Return.

- Notes:
  - Use EvaluateExprToInt helper to verify the other side is the literal 0 reliably through casts/macros.
  - This approach is robust even when roundup_pow_of_two is a macro, thanks to ExprHasName.

C) Optional: checkEndFunction / checkRegionChanges
- Not required. The state is path-sensitive and cleared per-path naturally. We only manage RoundupResMap through checkBind.

3) Reporting
- When a match is found in checkBranchCondition:
  - Create a non-fatal error node: if (!N) N = C.generateNonFatalErrorNode();
  - Prepare a short message:
    - “Do not detect overflow via !roundup_pow_of_two(); pre-validate the input first (UB on 32-bit).”
  - Use std::make_unique<PathSensitiveBugReport>(BugType, Msg, N); add the Condition source range as the primary range.
  - Emit with C.emitReport(...).

4) Heuristics and limits (to keep it simple and reduce noise)
- Only trigger on:
  - Direct ‘!’ or ‘== 0’ checks.
  - Either directly on the call in the condition, or on a variable known to hold the roundup result (from checkBind).
- Do not attempt alias tracking for integers.
- Do not attempt to verify existence of a prior “pre-check” guard; the zero-check pattern is considered suspicious on its own because it is unreliable across 32-bit arches.
- Do not rely on target bit-width; the checker flags the anti-pattern independent of compilation target.

5) Utilities used
- findSpecificTypeInChildren<T> to find CallExpr and DeclRefExpr inside both the bind statement and the branch condition.
- ExprHasName(E, "roundup_pow_of_two", C) to robustly recognize the macro/function name in source text.
- getMemRegionFromExpr to map a DeclRefExpr to its region key for RoundupResMap.
- EvaluateExprToInt to confirm integer-constant zero in comparisons.

6) Summary of control flow
- Assignment/Init from roundup_pow_of_two => mark LHS region in RoundupResMap.
- Any other assignment to that var => unmark.
- Branch condition:
  - If it directly tests roundup_pow_of_two(...) for zero => warn.
  - Else if it tests a var currently marked as roundup result for zero => warn.

Report message (short):
- “roundup_pow_of_two() overflow check via zero is unreliable (UB on 32-bit); pre-validate the input before calling.”
