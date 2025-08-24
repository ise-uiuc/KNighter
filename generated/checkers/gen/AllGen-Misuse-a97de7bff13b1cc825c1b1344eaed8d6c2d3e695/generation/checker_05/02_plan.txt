Plan to detect unsafe copy_from_sockptr in setsockopt handlers

1) Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(OptlenLBMap, const VarDecl*, uint64_t)
  - Tracks, per optlen parameter (ParmVarDecl*), the greatest proven lower bound for optlen on the current path.
  - We only store the lower bound value; if LB >= size used in copy_from_sockptr, the path is considered validated.

2) Helper identification utilities
- isSetSockoptHandler(const FunctionDecl *FD)
  - Return true if FD->getNameAsString() contains "setsockopt".
  - Additionally require that the function has a ParmVarDecl named "optlen" and a ParmVarDecl named "optval" to reduce noise.

- findOptlenParam(const FunctionDecl *FD)
  - Return the ParmVarDecl* for the parameter named "optlen" (must be integer type). Return nullptr if not present.

- isCopyFromSockptrLike(const CallEvent &Call, unsigned &SizeArgIndex)
  - Return true if callee name is "copy_from_sockptr" (SizeArgIndex = 2) or "copy_from_sockptr_offset" (SizeArgIndex = 3).
  - Return false for "bt_copy_from_sockptr" (explicitly ignore the safe helper).

- getConstSizeFromExpr(const Expr *E, CheckerContext &C, uint64_t &Out)
  - Use EvaluateExprToInt to resolve the size expression into a concrete constant.
  - Return true on success.

- extractOptlenCompare(const Stmt *Cond, const FunctionDecl *EnclosingFD, const ParmVarDecl *&OptlenPVD, const Expr *&SizeExpr, BinaryOperatorKind &Op, bool &OptlenOnLHS)
  - Parse the condition (ignoring implicit casts/paren) as BinaryOperator with op in {<, <=, >=, >, ==, !=}.
  - Identify if one side is a DeclRefExpr to the optlen ParmVarDecl and the other side is any integral expression.
  - Return true on success and fill outputs. We will later try to evaluate SizeExpr into a constant. Handle both orderings (optlen on LHS or RHS).

3) Branch reasoning (checkBranchCondition)
- Goal: Learn path-sensitive lower bounds for optlen derived from comparisons with sizeof(...) (or other integer constants).
- Steps:
  - Obtain the current enclosing FunctionDecl via Ctx.getLocationContext()->getDecl().
  - If not isSetSockoptHandler(FD), return.
  - Find optlen ParmVarDecl via findOptlenParam(FD). If null, return.
  - Attempt extractOptlenCompare(Condition, FD, OptlenPVD, SizeExpr, Op, OptlenOnLHS). If it fails, return.
  - Evaluate SizeExpr to constant uint64_t S using getConstSizeFromExpr. If it fails, return.
  - Decide which branch implies optlen >= bound:
    - If the comparison is:
      - optlen >= S (optlen on LHS): true branch implies LB >= S.
      - optlen > S: true branch implies LB >= S+1.
      - optlen < S: false branch implies LB >= S.
      - optlen <= S: false branch implies LB >= S+1.
      - optlen == S: true branch implies LB >= S.
      - optlen != S: neither branch guarantees a lower bound; ignore.
    - If optlen is on RHS, invert appropriately (e.g., S <= optlen is same as optlen >= S).
  - Create up to two successor states:
    - StateTrue = C.getState(); if true branch implies LB >= K, then set OptlenLBMap[OptlenPVD] = max(oldLB, K) in StateTrue.
    - StateFalse = C.getState(); if false branch implies LB >= K, then set OptlenLBMap[OptlenPVD] = max(oldLB, K) in StateFalse.
  - Emit both transitions with C.addTransition(StateTrue) and C.addTransition(StateFalse). If neither branch yields information, return without adding transitions (the engine will handle default splitting).

4) Detect unsafe copies (checkPreCall)
- Purpose: Flag calls that copy a fixed-size object from user without validating optlen or using the safe helper.
- Steps:
  - If not isCopyFromSockptrLike(Call, SizeArgIndex), return.
  - Retrieve the enclosing FunctionDecl (getLocationContext()->getDecl()). If not isSetSockoptHandler(FD), return.
  - Find optlen ParmVarDecl via findOptlenParam(FD). If null, return.
  - Extract size argument expression: const Expr *SizeArg = Call.getArgExpr(SizeArgIndex). Attempt getConstSizeFromExpr(SizeArg, C, CopySize). If fails, return (be conservative).
  - Retrieve current LB from OptlenLBMap for OptlenPVD. If no entry, treat LB = 0.
  - If LB >= CopySize, it is validated on this path; return.
  - Otherwise, report a bug:
    - Create a non-fatal error node (generateNonFatalErrorNode).
    - Message: "copy_from_sockptr uses fixed size without validating optlen"
    - Point to SizeArg source range. Optionally add a note if FD name contains "setsockopt": "Validate optlen >= sizeof(...) or use bt_copy_from_sockptr()".
    - Emit PathSensitiveBugReport.

5) Optional minimal noise control
- Only run this checker logic inside functions whose name contains "setsockopt" and that have both "optval" and "optlen" parameters. This keeps focus on the intended kernel handler pattern.
- Explicitly ignore calls to the safe helper "bt_copy_from_sockptr".

6) Callbacks summary and implementation notes
- checkBranchCondition
  - Parse relational conditions comparing the optlen parameter to a constant or sizeof expression.
  - Update OptlenLBMap on the corresponding branch using two addTransition calls.
- checkPreCall
  - Identify calls to copy_from_sockptr-like functions.
  - Evaluate the size argument to a constant.
  - Compare with current LB in OptlenLBMap; if insufficient, emit a report.
- No other callbacks required.

7) Utility Functions used
- EvaluateExprToInt to obtain the constant size from sizeof(T) or sizeof(var) in conditions and call arguments.
- Optionally, ExprHasName if you prefer to match function names, but using FD->getNameAsString() is sufficient here.

8) Report text
- Keep it short and clear:
  - Title: Unsafe copy_from_sockptr in setsockopt
  - Body: "copy_from_sockptr uses fixed size without validating optlen"
  - Suggestion note (optional): "Check optlen >= sizeof(...) or use bt_copy_from_sockptr()"

This plan detects the core bug pattern: a fixed-size copy_from_sockptr within a setsockopt handler without a preceding path constraint guaranteeing optlen >= that size. It remains conservative, path-sensitive, and avoids false positives when proper validation is present.
