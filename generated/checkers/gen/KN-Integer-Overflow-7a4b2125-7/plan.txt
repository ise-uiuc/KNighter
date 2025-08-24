1) Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResultMap, const VarDecl*, const Expr*)
  - Key: the variable that stores the result of roundup_pow_of_two().
  - Val: the argument expression passed to roundup_pow_of_two() (to correlate with possible pre-validation).
- REGISTER_SET_WITH_PROGRAMSTATE(ValidatedArgSet, const MemRegion*)
  - Tracks argument expressions that have been pre-validated by an upper-bound check (e.g., x > (1UL << ...)) before calling roundup_pow_of_two().

2) Helper utilities
- bool isRoundupPow2Call(const CallEvent &Call)
  - Return true if callee identifier is "roundup_pow_of_two".
- const VarDecl* getAssignedVarFromCall(const CallEvent &Call, CheckerContext &C)
  - Using findSpecificTypeInParents:
    - If parent is a BinaryOperator ‘=’ and RHS is this call, return LHS VarDecl.
    - Else if parent is a DeclStmt/VarDecl with init being this call, return that VarDecl.
- bool matchesZeroCheck(const Expr *Cond, const Expr *&CheckedExpr)
  - Return true if Cond is a zero-check on some expression:
    - UnaryOperator with opcode UO_LNot on expression E -> CheckedExpr = E.
    - BinaryOperator (==, <=) comparing an expression E to integer literal 0 in any side -> CheckedExpr = the non-zero side.
- bool isPrevalidationCheck(const Expr *Cond, const Expr *&ArgExprOut, const Expr *&BoundExprOut)
  - Return true if Cond is a relational compare (>, >=) and:
    - LHS is some expression E, RHS looks like a power-of-two bound (e.g., a shift Expr containing ‘<<’ or mentions BITS_PER_LONG).
    - To keep it simple:
      - If Cond is BinaryOperator > or >= and
      - findSpecificTypeInChildren<BinaryOperator>(RHS) shows opcode BO_Shl (<<), or
      - ExprHasName(RHS, "BITS_PER_LONG", C) is true,
      - then ArgExprOut = LHS, BoundExprOut = RHS.
- const MemRegion* exprToRegion(const Expr *E, CheckerContext &C)
  - Wrapper around getMemRegionFromExpr(E, C).

3) checkPostCall (record where roundup_pow_of_two result goes)
- Trigger: Every call. If isRoundupPow2Call(Call) is true:
  - Try getAssignedVarFromCall(Call, C); if returns VD:
    - Record RoundupResultMap[VD] = Call.getArgExpr(0) (the argument x).
  - Additionally, if this call later gets checked directly in an if-condition (no assigned var), that is handled in checkBranchCondition and does not need state here.

4) checkBranchCondition (detect both the bad pattern and the pre-validation)
- Step A: Mark pre-validated arguments
  - If isPrevalidationCheck(ConditionExpr, ArgExpr, BoundExpr) returns true:
    - const MemRegion *ArgReg = exprToRegion(ArgExpr, C);
    - If ArgReg != nullptr, add ArgReg to ValidatedArgSet.
- Step B: Find zero-checks
  - If matchesZeroCheck(ConditionExpr, CheckedExpr) is true:
    - Case B1: CheckedExpr is a CallExpr to roundup_pow_of_two:
      - Extract its argument ArgExpr = call->getArg(0).
      - Get ArgReg = exprToRegion(ArgExpr, C).
      - If ArgReg is not in ValidatedArgSet:
        - Report bug at this condition: “Unreliable overflow check: testing roundup_pow_of_two() result for 0; pre-check the input against 1UL << (BITS_PER_LONG - 1).”
    - Case B2: CheckedExpr is a reference to a variable (DeclRefExpr):
      - Get VD = cast<DeclRefExpr>(...).getDecl()->getCanonicalDecl().
      - Lookup RoundupResultMap[VD] -> ArgExpr. If found:
        - Get ArgReg = exprToRegion(ArgExpr, C).
        - If ArgReg not in ValidatedArgSet:
          - Report the same bug at this condition site.
- Notes:
  - This catches both patterns:
    - Direct: if (!roundup_pow_of_two(x)) ...
    - Indirect: n = roundup_pow_of_two(x); if (!n) ...

5) Reporting
- Create a non-fatal error node with generateNonFatalErrorNode.
- Use std::make_unique<PathSensitiveBugReport> with a short message:
  - “Do not test roundup_pow_of_two() result for 0; pre-validate input to avoid UB on 32-bit.”
- Point the primary location to the branch condition expression.
- Optionally add a note at the call to roundup_pow_of_two (if available, e.g., from RoundupResultMap parent) to aid diagnosis.

6) Other callbacks
- checkBind: not needed (we purposely keep the pattern simple and only match the common case of direct variable receiving the call result).
- checkLocation / evalAssume / checkRegionChanges / checkEndFunction: not needed.

7) False-positive control (simple and robust)
- We suppress the warning if we have seen a pre-validation on the same argument expression on the same path:
  - Pre-validation is recognized heuristically by “x > (1 << ...)" or “x > something mentioning BITS_PER_LONG”.
  - Because ValidatedArgSet is path-sensitive state, it naturally models “pre-check before call.”
- We intentionally do not try to resolve complex aliasing or arithmetic on the result variable or the argument; the checker focuses on the common, simple pattern to minimize complexity and false positives.

8) Summary of flow
- Record: When roundup_pow_of_two is used to initialize/assign a variable, store VarDecl -> ArgExpr.
- Mark: When encountering if (x > 1UL << ...) style conditions, mark x as pre-validated (ValidatedArgSet insert).
- Warn: When encountering if (!roundup_pow_of_two(x)) or if (!n) and n maps back to roundup_pow_of_two(x), and x is not pre-validated, emit a diagnostic.
