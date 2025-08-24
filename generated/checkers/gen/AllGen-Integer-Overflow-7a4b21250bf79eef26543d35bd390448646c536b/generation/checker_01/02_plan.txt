1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(RoundupSymMap, SymbolRef, const CallExpr*)
  - Purpose: remember which symbolic values come from roundup_pow_of_two(), so later zero checks on these symbols can be flagged.
  - Key = the SymbolRef representing the value produced by the call (the same symbol that will be used when the code does if (!n) or if (n == 0)).
  - Value = the CallExpr* of the roundup_pow_of_two() call (for pinpointing and messages).


2) Callbacks and how to implement them

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const

- Goal: Record when a variable is assigned from roundup_pow_of_two(...) so that future zero checks on that variable can be detected.
- Steps:
  1. Extract the RHS CallExpr within S, if any:
     - Use findSpecificTypeInChildren<CallExpr>(S).
     - If not found, return.
  2. Validate the callee:
     - Get callee identifier and ensure it’s "roundup_pow_of_two".
     - If not, return.
  3. Get the symbol for the assigned value:
     - From Val.getAsSymbol() (ignore if null).
  4. Record in program state:
     - State = State.set<RoundupSymMap>(Sym, CE).
     - C.addTransition(State).
  5. Optional alias support (simple, low-cost):
     - If RHS is a symbol that already exists in RoundupSymMap and this bind does not involve a call (e.g., m = n;), we do nothing special: the analyzer typically propagates the same symbol to the LHS when no transformation is applied. This keeps the solution simple.


B) checkBranchCondition(const Stmt *Condition, CheckerContext &C) const

- Goal: Identify the unreliable overflow check pattern:
  - if (!roundup_pow_of_two(x))
  - if (!n) where n is previously bound to roundup_pow_of_two(x)
  - if (roundup_pow_of_two(x) == 0)
  - if (n == 0) where n is previously bound to roundup_pow_of_two(x)
- Limit to 32-bit unsigned long targets to reduce noise.
- Steps:
  1. Early filter for 32-bit unsigned long target:
     - const ASTContext &ACtx = C.getASTContext();
     - If ACtx.getTypeSize(ACtx.UnsignedLongTy) != 32, return (no warning).
  2. Normalize the condition:
     - const Expr *Cond = dyn_cast_or_null<Expr>(Condition); if (!Cond) return;
     - Cond = Cond->IgnoreParenImpCasts();
  3. Case 1: Unary logical not (!E)
     - If Cond is a UnaryOperator with opcode UO_LNot:
       - Let E = UO->getSubExpr()->IgnoreParenImpCasts().
       - Detect direct call:
         - If E is a CallExpr with callee name "roundup_pow_of_two", report (see reporting below).
       - Else detect symbol derived from a previous call:
         - SVal SV = C.getSVal(E);
         - If SymbolRef Sym = SV.getAsSymbol():
           - Look up Sym in RoundupSymMap; if present, report.
  4. Case 2: Equality comparison (E == 0) or (0 == E)
     - If Cond is a BinaryOperator with opcode BO_EQ:
       - Let LHS = BO->getLHS()->IgnoreParenImpCasts();
       - Let RHS = BO->getRHS()->IgnoreParenImpCasts();
       - Use EvaluateExprToInt to check whether either side is the integer constant zero.
         - If RHS evaluates to 0:
           - Inspect LHS as in step 3 (direct CallExpr or symbol mapped in RoundupSymMap).
         - Else if LHS evaluates to 0:
           - Inspect RHS similarly.
     - Note: We intentionally do not warn for "!= 0" or for "if (n)" without logical not, since the buggy pattern is specifically using zero-result as an overflow indicator.
  5. Reporting:
     - Use C.generateNonFatalErrorNode() to create the error node; if null, return.
     - Create a PathSensitiveBugReport with a short message:
       - "Unreliable overflow check: testing roundup_pow_of_two result against 0 on 32-bit."
     - Add a note suggesting the correct approach:
       - "Pre-check the input before calling, e.g., x > 1UL << (BITS_PER_LONG - 1)."
     - Anchor the report at the current BranchCondition statement.
     - C.emitReport(std::move(R)).


3) Optional helper logic (inline within callbacks)

- bool isRoundupPow2Call(const Expr *E, const CallExpr *&OutCE):
  - If E is a CallExpr, get callee Identifier and match "roundup_pow_of_two".
  - Return true and set OutCE; else false.

- bool isZeroExpr(const Expr *E, CheckerContext &C):
  - Use EvaluateExprToInt to check if it’s a constant integer value equal to 0.

- The provided utility findSpecificTypeInChildren<CallExpr>(S) helps in checkBind to find the RHS call expression under the assignment or initialization statement.

- For robustness, always IgnoreParenImpCasts() when examining expressions.


4) Rationale and scope control

- This checker intentionally warns only when:
  - The build target’s unsigned long is 32-bit (ASTContext UnsignedLongTy size equals 32), which is the environment where roundup_pow_of_two may hit UB via a left shift of 32.
  - A zero check is used as the overflow detection on the result of roundup_pow_of_two.
- We do not attempt to prove the existence of an adequate pre-check; keeping the checker simple avoids complex control-flow reasoning and reduces false positives in practice.
- Both uses directly in conditions and via variables assigned from the function call are covered.


5) Selected APIs used

- Program state:
  - REGISTER_MAP_WITH_PROGRAMSTATE(RoundupSymMap, SymbolRef, const CallExpr*)
- Callbacks:
  - checkBind to record symbols produced by roundup_pow_of_two()
  - checkBranchCondition to detect if (!n) or (n == 0) patterns (including direct call in condition)
- Utilities:
  - findSpecificTypeInChildren<CallExpr>
  - EvaluateExprToInt
  - Lexer/getSourceManager not needed
- Bug report:
  - generateNonFatalErrorNode, PathSensitiveBugReport, C.emitReport


6) Report message

- Title: "Unreliable overflow check: testing roundup_pow_of_two result against 0 on 32-bit."
- One-line note: "Pre-check the input before calling, e.g., x > 1UL << (BITS_PER_LONG - 1)."
