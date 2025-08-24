Plan: Detect unsafe copy_from_sockptr in setsockopt paths (missing optlen validation or partial copy)

1) Program state
- REGISTER_SET_WITH_PROGRAMSTATE(PartialLenVars, const MemRegion*)
  - Purpose: Track length variables that were computed from optlen via min/min_t/sizeof, i.e., “partial copy” length sources. The set stores the MemRegion of such length variables.

No other custom state is necessary.

2) Helper predicates and utilities
- bool isCopyFromSockptr(const CallEvent &Call)
  - Return true if callee name equals "copy_from_sockptr".
- bool isBtCopyFromSockptr(const CallEvent &Call)
  - Return true if callee name equals "bt_copy_from_sockptr" (safe helper).
- const FunctionDecl* getEnclosingFunction(const CheckerContext &C)
  - Return the current FunctionDecl from C.getLocationContext()->getDecl().
- bool isSetsockoptLike(const FunctionDecl *FD)
  - True if:
    - FD->getNameAsString() contains "setsockopt", OR
    - FD has a parameter named "optlen" (and optionally "optval"); prefer name checks per Suggestions note.
- const VarDecl* getAddrOfVar(const Expr *E)
  - If E is UnaryOperator(&) of a DeclRefExpr, return the VarDecl. Otherwise return nullptr.
- const MemRegion* getLenRegionIfDeclRef(const Expr *LenE, CheckerContext &C)
  - If LenE is a DeclRefExpr to a local/param variable, return its MemRegion via getMemRegionFromExpr.
- bool lenExprSuggestsPartialCopy(const Expr *LenE, CheckerContext &C)
  - Use ExprHasName to detect “min”, “min_t” or the presence of “optlen” in the LenE source text. If any match, return true.
- bool getDestVarAndSize(const Expr *DstE, CheckerContext &C, const VarDecl* &VD, uint64_t &SizeBytes)
  - If DstE takes address-of a local (getAddrOfVar), get VD. Then compute SizeBytes with C.getASTContext().getTypeSizeInChars(VD->getType()).getQuantity(). Return true on success.
- bool hasPrecedingOptlenGuard(const Stmt *CallSite, const VarDecl *VD, CheckerContext &C)
  - Heuristic guard detection:
    - Find the nearest enclosing CompoundStmt using findSpecificTypeInParents<CompoundStmt>(...).
    - Iterate its children statements in source order; stop at CallSite.
    - For each preceding IfStmt:
      - Extract Condition and its source via ExprHasName:
        - Confirm it mentions "optlen".
        - Confirm it mentions "sizeof" and VD->getName().
        - Confirm it mentions either "<" or "<=" or "!=".
      - If true, consider this a validation guard and return true.
    - Otherwise return false.
  - Rationale: Accepts the common “if (optlen < sizeof(obj)) return/break;” pattern. It’s a syntactic, best-effort filter to reduce false positives.

3) Callbacks

A) checkPostStmt(const DeclStmt *DS)
- Goal: Seed PartialLenVars for declarations like “size_t len = min_t(..., optlen)” or “size_t len = min(sizeof(obj), optlen)”.
- Steps:
  - For each VarDecl in DS with an initializer:
    - If ExprHasName(Init, "optlen", C) AND (ExprHasName(Init, "min", C) OR ExprHasName(Init, "min_t", C) OR ExprHasName(Init, "sizeof", C)):
      - Get its MemRegion via getMemRegionFromExpr on a DeclRefExpr to that Var (you can synthesize a DRE or take from the VarDecl’s storage Expression region through the StoreManager).
      - Insert that region into PartialLenVars.

B) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
- Goal: Also detect assignment-based seeding, e.g., “len = min_t(..., optlen);”.
- Steps:
  - If S is a BinaryOperator of kind BO_Assign:
    - Extract LHS (length variable) and RHS (expression).
    - If LHS is a DeclRefExpr to a variable and RHS satisfies:
      - ExprHasName(RHS, "optlen", C) AND (ExprHasName(RHS, "min", C) OR ExprHasName(RHS, "min_t", C) OR ExprHasName(RHS, "sizeof", C)):
        - Get region for LHS via getMemRegionFromExpr and insert into PartialLenVars.

C) checkPostCall(const CallEvent &Call, CheckerContext &C)
- Filter and context:
  - If isBtCopyFromSockptr(Call), return (safe).
  - If not isCopyFromSockptr(Call), return.
  - Obtain enclosing FunctionDecl FD. If !isSetsockoptLike(FD), return (to keep scope focused and reduce false positives).
- Analyze arguments:
  - DestE = AST node of arg0 (destination), LenE = AST node of arg2 (length).
  - If lenExprSuggestsPartialCopy(LenE, C) is true:
    - Report “setsockopt copy allows short input; may leave object uninitialized. Use bt_copy_from_sockptr or validate optlen.”
    - Rationale: Direct use of optlen or min/min_t in length is the “partial copy” pattern.
  - Else, if LenE is a DeclRefExpr:
    - Get region via getLenRegionIfDeclRef; if region is in PartialLenVars:
      - Report the same “partial copy” diagnostic.
  - Else, attempt to detect missing validation for fixed-size copies:
    - If getDestVarAndSize(DestE, C, VD, SizeBytes) succeeds:
      - Heuristically consider this call unsafe unless a guard exists:
        - If hasPrecedingOptlenGuard(CallExprNode, VD, C) returns true: do nothing (consider validated).
        - Else: Report “copy_from_sockptr without validating optlen >= sizeof(dest).”
    - If not able to extract VD (e.g., destination is not &var) AND LenE is clearly a constant size (EvaluateExprToInt succeeds or ExprHasName(LenE, "sizeof", C)):
      - Report the same “missing validation” warning (destination unknown, but fixed-size copy in setsockopt without visible validation).
- Bug report:
  - Use generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>.
  - Keep message short:
    - For partial copy: “Partial setsockopt copy; input shorter than struct may leave fields uninitialized.”
    - For missing guard: “Missing optlen >= sizeof(...) check before copy_from_sockptr.”

4) Notes to reduce false positives
- Only run the checks when isSetsockoptLike(FD) is true (function name contains “setsockopt” or has param named “optlen”).
- Treat bt_copy_from_sockptr as safe and skip.
- Before reporting the “missing guard” for fixed-size copies, attempt hasPrecedingOptlenGuard to accept the common safe pattern.
- For “partial copy” detection, prefer strong syntactic cues:
  - Len expr includes “optlen” or “min/min_t”, or Len variable was previously computed from optlen+min/sizeof (via PartialLenVars).

5) Where each utility helps
- ExprHasName: Detect “optlen”, “min”, “min_t”, “sizeof” in expressions and conditions.
- findSpecificTypeInParents: Find enclosing CompoundStmt to scan earlier sibling IfStmt for guards.
- EvaluateExprToInt: Recognize constant sizes in the length argument.
- getMemRegionFromExpr: Map DeclRefExpr of length variables into MemRegion for PartialLenVars tracking.

This plan yields:
- Detection of the exact buggy cases in the patch:
  - rfcomm_sock_setsockopt_old: copy_from_sockptr(&opt, optval, sizeof(u32)) with no validation -> “missing guard.”
  - rfcomm_sock_setsockopt: len = min_t(..., optlen); copy_from_sockptr(&sec, optval, len) -> “partial copy.”
