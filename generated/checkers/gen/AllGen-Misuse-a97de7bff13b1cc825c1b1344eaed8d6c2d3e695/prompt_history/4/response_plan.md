1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(OptlenLBMap, const ParmVarDecl*, uint64_t)
  - Per-path lower-bound knowledge: for a given function parameter “optlen”, record the greatest lower bound (in bytes) that has been validated along the current path. We only need a single lower bound number per “optlen” parm; update it to the max of the existing bound and the newly learned bound.

No other custom state is necessary.


2) Callbacks and how to implement

A) evalAssume(State, CondSVal, Assumption)
- Goal: Learn “optlen >= sizeof(X)” style facts from branch conditions.
- Steps:
  1) Retrieve the Stmt* for Cond from the current node if available or use a helper to map SVal back to Stmt when possible (CheckerContext usually provides the branch condition Stmt via checkBranchCondition; however, evalAssume gives us Cond as SVal, which is fine for constraint but not to parse structure. Implement the learning in checkBranchCondition instead to reliably parse the AST of the condition. If you prefer evalAssume, ensure you can access the original Stmt. For simplicity and robustness, do this learning in checkBranchCondition).
  2) Return unchanged State (we won’t implement learning here; see B).

B) checkBranchCondition(const Stmt *Condition, CheckerContext &C)
- Goal: Parse if-conditions to capture validations like “if (optlen < sizeof(X)) … else …” or “if (optlen >= sizeof(X)) …”.
- Steps:
  1) If Condition is not a BinaryOperator, return.
  2) Extract LHS and RHS.
  3) Identify if either LHS or RHS is a DeclRefExpr whose decl name is exactly “optlen”.
     - Use dyn_cast<DeclRefExpr> and DRE->getDecl()->getNameAsString() == "optlen".
     - If not found, return.
     - Record the ParmVarDecl* for that “optlen” (cast the Decl to ParmVarDecl).
  4) For the side that is not “optlen”, try to evaluate it to a constant byte size:
     - Accept UnaryExprOrTypeTraitExpr (sizeof) and any constant expression.
     - Use EvaluateExprToInt(APSInt, Expr, C). If fails, return (we only handle constant size).
     - Let SizeConst = EvalRes.getZExtValue().
  5) Based on Operator and branch direction:
     - We need to know which branch we are analyzing. For branch conditions, the engine explores both; our callback is pre-visit. Instead of branching here, we will record knowledge in both successors using C.assume; However, for simplicity and stability: do nothing here and rely on the analyzer’s splitting; We will re-derive lower-bound knowledge in checkPreCall by querying the path constraints. Since we don’t have direct min/max queries provided, implement the learning here using both successor nodes:
       - Generate two assumptions using C.assume() on the condition SVal:
         - TrueState: Assumption that Condition is true.
         - FalseState: Assumption that Condition is false.
       - For each non-null successor state:
         - Determine if that assumption implies optlen >= SizeConst:
            • If op is “optlen < K”: FalseState implies optlen >= K. On FalseState: set OptlenLBMap[Parm] = max(old, K).
            • If op is “optlen <= K”: FalseState implies optlen > K (>= K+1). Set LB to K (conservative) or K+1; either is fine since we compare to sizeof(X). Use K to keep it simple.
            • If op is “optlen >= K”: TrueState implies LB >= K.
            • If op is “optlen > K”: TrueState implies LB >= K (conservative).
            • If op is “optlen == K”: TrueState implies LB >= K.
            • If condition is reversed (K < optlen, K <= optlen, etc.), flip the logic accordingly and apply the same mapping.
       - For each successor where we updated LB, call C.addTransition(NewState).
     - If we cannot split (rare), skip updating.
  Note: This keeps the knowledge path-sensitive by producing both transitions with updated state.

C) checkPreCall(const CallEvent &Call, CheckerContext &C)
- Goal: Detect dangerous copies and report if “optlen” wasn’t validated for the fixed size being copied.
- Steps:
  1) Restrict to setsockopt handlers to reduce false positives:
     - Retrieve the current function: if const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl()) and FD->getNameAsString().contains("setsockopt") is false, return.
  2) Identify unsafe copy helpers:
     - Get callee name via Call.getCalleeIdentifier()->getName().
     - If name == "bt_copy_from_sockptr": safe, return.
     - If name == "copy_from_sockptr":
         • arg indices: dst=0, src=1, size=2.
     - If name == "copy_from_sockptr_offset":
         • arg indices: dst=0, src=1, offset=2, size=3.
     - Else return.
  3) Check the second argument (src) contains “optval”:
     - Use ExprHasName(Call.getArgExpr(srcIndex), "optval", C). If false, return.
  4) Check the size argument is a fixed constant “sizeof(...)”:
     - Try EvaluateExprToInt on the size argument. If it fails, return (we only flag fixed-sized copies).
     - Let CopySize = evaluated constant.
  5) Find the “optlen” parameter in the current function:
     - Iterate FD->parameters() and find ParmVarDecl* where getNameAsString() == "optlen".
     - If not found, return.
  6) Query our learned lower bound:
     - State = C.getState().
     - Get LB = OptlenLBMap[Parm]. If no entry, treat as 0.
  7) If LB < CopySize, report a bug:
     - Create ExplodedNode *N = C.generateNonFatalErrorNode().
     - If N is null, return.
     - Emit PathSensitiveBugReport:
       • BugType: “Unchecked optlen in setsockopt copy”.
       • Message: “copy_from_sockptr with fixed size without checking optlen”.
       • Location: the CallExpression of copy_from_sockptr (Call.getSourceRange()).
     - Otherwise, do nothing (the path is safe because validation enforces optlen >= CopySize).

D) Optional: checkBeginFunction(CheckerContext &C)
- Not strictly required. Program state maps are initially empty per path. No initialization needed.

E) Other callbacks
- checkPostCall, checkBind, checkLocation, checkEndFunction, checkEndAnalysis: not necessary for this checker’s simplest implementation.


3) Heuristics and notes

- Validation we recognize:
  - if (optlen < sizeof(X)) return ...; then later copy sizeof(X) is safe on the false branch; our checkBranchCondition logic records LB on the false successor.
  - if (optlen >= sizeof(X)) { copy sizeof(X); } is safe on the true branch; LB is recorded on the true successor.
  - if (optlen == sizeof(X)) also safe on true branch.
- We conservatively skip:
  - Non-constant sizes, including “len = min_t(..., sizeof(X), optlen)” followed by copy_from_sockptr(..., len). This is not the “fixed-sized copy” pattern; we don’t warn to keep the checker simple and precise.
- We only consider sources whose expression text contains “optval” to match setsockopt signature and avoid false positives with other sockptr sources.
- We treat bt_copy_from_sockptr as safe and do not warn on it.


4) Utility helpers to include

- A small helper to extract CopySize:
  - bool tryEvalToConst(const Expr *E, uint64_t &Out, CheckerContext &C)
    • use EvaluateExprToInt; on success set Out = EvalRes.getZExtValue().

- A helper to get the optlen ParmVarDecl* from the current FD:
  - const ParmVarDecl* getOptlenParm(const FunctionDecl *FD)
    • iterate parameters and match name “optlen”.

- A helper to update LB in OptlenLBMap:
  - ProgramStateRef setLB(ProgramStateRef S, const ParmVarDecl *P, uint64_t NewLB)
    • retrieves old, stores max(old, NewLB).


5) Reporting

- Use generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>.
- Message: “copy_from_sockptr with fixed size without checking optlen”.
- Keep it short and clear as requested.
