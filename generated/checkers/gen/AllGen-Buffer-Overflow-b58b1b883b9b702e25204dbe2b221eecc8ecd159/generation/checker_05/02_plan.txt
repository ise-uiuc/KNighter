Plan

1) Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(ShortenBaseMap, const MemRegion*, const MemRegion*)
  - Key: MemRegion of the temporary “shorten” variable.
  - Value: MemRegion of the “total/count” base object (e.g., the iter pointer used by iov_iter_count(iter), or the base of a MemberExpr like iter->count).
- REGISTER_MAP_WITH_PROGRAMSTATE(ShortenGuardedMap, const MemRegion*, bool)
  - Key: MemRegion of the “shorten” variable.
  - Value: whether there appears to be a guard/clamp (true) observed before use.

Rationale: We only need to remember that a variable was computed as an unsigned difference with a round_up/ALIGN on the right-hand side, what total/base object it relates to, and if a guard was observed. No further aliasing/state is necessary.

2) Helper predicates and utilities
- isUnsignedIntLike(QualType QT): return true if QT is an unsigned integer type (including size_t).
- exprContainsRoundUp(const Expr *E, CheckerContext &C): return true if ExprHasName(E, "round_up") || ExprHasName(E, "ALIGN") || ExprHasName(E, "roundup") (cover typical spellings/macros).
- tryGetBaseRegionFromTotalExpr(const Expr *E, CheckerContext &C) -> const MemRegion*
  - If E is a MemberExpr like X->count or X.len, return getMemRegionFromExpr(MemberExpr->getBase()).
  - Else if E is a CallExpr named iov_iter_count (or similar), return getMemRegionFromExpr(its first argument).
  - Otherwise return nullptr.
- getShortenVarRegion(const Expr *LHS, CheckerContext &C) -> const MemRegion*
  - If LHS is a DeclRefExpr, use getMemRegionFromExpr to get its region; else nullptr.
- getBaseRegionFromLHS(const Expr *LHS, CheckerContext &C) -> const MemRegion*
  - If LHS is MemberExpr, return getMemRegionFromExpr(MemberExpr->getBase()); else nullptr.

3) checkPostStmt(const DeclStmt *DS)
Purpose: Detect declarations that compute the “shorten” variable as an unsigned subtraction of a round_up/ALIGNed value and record base relationship.
Implementation details:
- Iterate VarDecls in DS; for each with an initializer:
  - Ensure VarDecl type isUnsignedIntLike.
  - If the initializer is a BinaryOperator with opcode BO_Sub:
    - Let U = LHS, W = RHS of the subtraction.
    - If !exprContainsRoundUp(W, C), skip.
    - Try to infer base region from U using tryGetBaseRegionFromTotalExpr(U, C). If nullptr, skip.
    - Obtain MemRegion of the declared variable (shorten) via getMemRegionFromExpr on a DeclRefExpr built from VarDecl (or extract from the initializer binding in state if available).
    - Record ShortenBaseMap[shortenReg] = baseReg and ShortenGuardedMap[shortenReg] = false.

4) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
Two responsibilities:
A) Track non-declarative assignments that compute “shorten”.
- If S is a BinaryOperator with opcode BO_Assign:
  - Let LHS be the assigned expression; get shortenReg via getShortenVarRegion(LHS, C). If nullptr, skip.
  - Let RHS = assigned value; if RHS is BinaryOperator BO_Sub with RHS expr W and exprContainsRoundUp(W, C):
    - Extract U = LHS of the subtraction; obtain baseReg via tryGetBaseRegionFromTotalExpr(U, C). If nullptr, skip.
    - Record ShortenBaseMap[shortenReg] = baseReg and ShortenGuardedMap[shortenReg] = false.

B) Detect and warn on subtracting “shorten” from the corresponding count without a guard.
- Case 1: Compound subtraction “X -= shorten”
  - If S is a CompoundAssignOperator with opcode BO_SubAssign:
    - Let LHS be the target; get lhsBaseReg via getBaseRegionFromLHS(LHS, C). If nullptr, skip.
    - Let RHS be the expression; if RHS is a DeclRefExpr, get its region rShorten; check ShortenBaseMap contains rShorten.
    - If ShortenBaseMap[rShorten] == lhsBaseReg and ShortenGuardedMap[rShorten] is false, report bug.
    - Optional: after reporting or confirming safe, remove rShorten from maps to reduce noise on repeated uses.
- Case 2: “X = X - shorten”
  - If S is a BinaryOperator with opcode BO_Assign:
    - Let LHS be target location locL; also attempt to get MemRegion of LHS (e.g., for MemberExpr base via getBaseRegionFromLHS(LHS, C) as lhsBaseReg).
    - Let RHS be BinaryOperator BO_Sub. If not, skip.
    - Check RHS RHSOperand is DeclRefExpr to rShorten; check ShortenBaseMap contains rShorten.
    - Also ensure RHS LHSOperand semantically refers to the same target as the assignment’s LHS:
      - Compare base region of RHS LHSOperand (if a MemberExpr, use getBaseRegionFromLHS) against lhsBaseReg.
    - If equal and ShortenGuardedMap[rShorten] is false, report bug.

Report message: "Possible unsigned underflow: subtracting rounded-up length from total without bounds check."

5) checkBranchCondition(const Stmt *Condition, CheckerContext &C)
Purpose: Mark “shorten” as guarded if we observe a comparison check that likely clamps or validates it.
Implementation details:
- Attempt dyn_cast<BinaryOperator>(Condition). If not comparison, return.
- If comparison opcode is one of BO_GE, BO_GT, BO_LE, BO_LT:
  - Inspect if either side contains a DeclRefExpr for a variable whose region is in ShortenBaseMap (use findSpecificTypeInChildren<DeclRefExpr> and getMemRegionFromExpr).
  - If a rShorten is found:
    - Optionally check that the other side references the corresponding total (heuristics):
      - If other side has a MemberExpr where getBaseRegionFromLHS(MemberExpr, C) == ShortenBaseMap[rShorten], or
      - Other side contains a call like iov_iter_count(...) whose argument region equals ShortenBaseMap[rShorten], or
      - ExprHasName(otherSide, "count") is true and ShortenBaseMap[rShorten] is non-null.
    - If heuristic matches, set ShortenGuardedMap[rShorten] = true.
Rationale: We approximate that such a comparison implies a clamp/check against the total. This suppresses warnings when authors explicitly verify bounds (e.g., if (shorten >= iter->count) shorten = 0;).

6) Notes on robustness and precision
- round_up/ALIGN are often macros; use ExprHasName in exprContainsRoundUp to robustly catch them in source text.
- The base association relies on either:
  - MemberExpr bases (e.g., iter->count), or
  - Known count getters like iov_iter_count(iter) where we use the first argument’s region as the base.
- If either side cannot be resolved to a MemRegion, skip to avoid false positives.
- Keep the checker conservative: only warn when:
  - A “shorten” is computed from an unsigned subtraction with a round-up on RHS, and
  - That “shorten” is subsequently used to decrease a count tied to the same base object, and
  - No guard was observed.

7) Bug report emission
- When the pattern matches and ShortenGuardedMap[shorten] is false:
  - Node N = C.generateNonFatalErrorNode();
  - Create a PathSensitiveBugReport with a concise message:
    - Title: "Underflow risk in count adjustment"
    - Message: "Possible unsigned underflow: subtracting rounded-up length from total without bounds check."
  - Point the primary location to the subtraction statement (the '-=' or 'X = X - shorten').
  - Optionally add a note at the “shorten” computation site (retrieve from S pointer when recorded) if available.

8) Callback selection summary
- checkPostStmt(DeclStmt): record “shorten = U - round_up(...)” patterns at declaration-initializer time.
- checkBind(...): record assignment-based patterns; and detect/warn when “shorten” is used in a subtraction against the corresponding base count.
- checkBranchCondition(...): mark “shorten” as guarded if a comparison with the corresponding base count is observed.

This minimal, path-sensitive plan targets the kernel pattern that caused the iov_iter count underflow, and will also catch similar unsigned subtractions against rounded-up sizes that are later subtracted from related size/count fields without a prior clamp.
