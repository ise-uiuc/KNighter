Plan

1) Program state
- Register one map to remember variables that just received the result of roundup_pow_of_two():
  - REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResMap, const MemRegion *, const Expr *)
  - Key: the destination variable’s MemRegion.
  - Value: the (single) argument expression passed to roundup_pow_of_two (to help produce a better diagnostic). If you don’t need it in the message, you can store a dummy pointer or a bool instead.

Rationale: We only need to know whether a particular variable was assigned from roundup_pow_of_two(). No complex aliasing or lifetime tracking is necessary; we clear/rewrite the tag on subsequent assignments.

2) Callback selection and implementation

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
Goal: Tag the LHS variable if it’s assigned from roundup_pow_of_two(arg), propagate/clear tags on other assignments.

Implementation steps:
- Extract the destination region:
  - If Loc is not a loc::MemRegionVal or the region is not a VarRegion, return.
  - const MemRegion *DstR = Loc.castAs<loc::MemRegionVal>().getRegion();
- Identify the RHS expression of this bind from S:
  - If S is a BinaryOperator with isAssignmentOp(), let RHS = BO->getRHS()->IgnoreParenImpCasts().
  - Else if S is a DeclStmt with a single VarDecl that has an initializer, let RHS = VD->getInit()->IgnoreParenImpCasts().
  - Otherwise, best-effort fallback: use findSpecificTypeInChildren<CallExpr>(S) if needed (but prefer the two direct cases above).
- Case 1: RHS is a call to roundup_pow_of_two:
  - Check call by:
    - If RHS is CallExpr CE and ExprHasName(CE, "roundup_pow_of_two", C) is true.
  - If true:
    - const Expr *Arg0 = CE->getNumArgs() > 0 ? CE->getArg(0) : nullptr.
    - State = State->set<RoundupResMap>(DstR, Arg0);
    - C.addTransition(State).
  - Return.
- Case 2: Propagate tag on simple copies:
  - If RHS is a DeclRefExpr DRE:
    - const MemRegion *SrcR = getMemRegionFromExpr(DRE, C).
    - If SrcR found and State has entry for SrcR in RoundupResMap, then:
      - State = State->set<RoundupResMap>(DstR, State->get<RoundupResMap>(SrcR));
      - C.addTransition(State).
      - Return.
- Default: Clear any prior tag for DstR when this assignment is not from roundup:
  - If State contains DstR, State = State->remove<RoundupResMap>(DstR); C.addTransition(State).

Notes:
- This keeps the map precise: only the most recent assignment governs the tag.
- No alias map is needed because we are tracking scalars that are assigned by value.

B) checkBranchCondition(const Stmt *Condition, CheckerContext &C) const
Goal: Detect the buggy overflow check pattern where code tests the result of roundup_pow_of_two for zero after the call.

We emit a warning only on 32-bit unsigned long targets.

Implementation steps:
- Gate by target type size:
  - const ASTContext &ACtx = C.getASTContext();
  - unsigned ULWidth = ACtx.getIntWidth(ACtx.UnsignedLongTy);
  - If ULWidth != 32, return (do not warn on 64-bit).
- Prepare small helpers:
  - isZeroExpr(const Expr *E):
    - Use EvaluateExprToInt to constant-fold; return true iff value == 0.
  - isRoundupCall(const Expr *E):
    - Return true if E is a CallExpr and ExprHasName(E, "roundup_pow_of_two", C).
- Analyze the condition expression:
  - const Expr *Cond = dyn_cast<Expr>(Condition); if (!Cond) return;
  - Cond = Cond->IgnoreParenImpCasts().
- Pattern P1: Direct zero-check of a variable that came from roundup_pow_of_two:
  - If Cond is a UnaryOperator UO_LNot:
    - const Expr *Sub = U->getSubExpr()->IgnoreParenImpCasts();
    - If Sub is a DeclRefExpr:
      - const MemRegion *R = getMemRegionFromExpr(Sub, C);
      - If R and State has R in RoundupResMap, then report.
  - Else if Cond is a BinaryOperator BO with opcode BO_EQ:
    - const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    - const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
    - If (L is DeclRefExpr tracked in RoundupResMap and isZeroExpr(RHS)) OR
         (RHS is DeclRefExpr tracked and isZeroExpr(L)):
      - report.
- Pattern P2: Direct zero-check on the call itself:
  - If Cond is UnaryOperator UO_LNot:
    - const Expr *Sub = U->getSubExpr()->IgnoreParenImpCasts();
    - If isRoundupCall(Sub), report.
  - Else if Cond is BinaryOperator BO with opcode BO_EQ:
    - const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    - const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
    - If (isRoundupCall(L) and isZeroExpr(RHS)) OR
         (isRoundupCall(RHS) and isZeroExpr(L)):
      - report.

Bug reporting:
- Create a BugType once (e.g., in the checker constructor) with a short name like "Misuse of roundup_pow_of_two overflow check".
- Create a non-fatal error node and emit a short message:
  - "Do not detect overflow by testing roundup_pow_of_two(x) == 0; on 32-bit, check x <= (1UL << 31) before calling."
- Use the condition’s source range as the primary location.
- Optionally, if you stored Arg0 in RoundupResMap, add a note to point to the original argument expression to help the user identify what should be pre-validated.

3) Optional pattern coverage and pruning
- The above detects the canonical buggy idiom:
  - n = roundup_pow_of_two(x); if (!n) ...
  - if (!roundup_pow_of_two(x)) ...
  - if (n == 0) ... with n tagged as from roundup.
- We do not warn on 64-bit targets to avoid false positives.
- We clear tags on any non-roundup assignment to keep state precise and avoid stale reports.

4) Utility functions used
- ExprHasName to recognize "roundup_pow_of_two" even if it is a macro.
- EvaluateExprToInt to test if an expression is 0.
- getMemRegionFromExpr to map DeclRefExprs to regions for state lookup.
- findSpecificTypeInChildren may be used as a fallback in checkBind if needed to locate the RHS call when S is complex.
