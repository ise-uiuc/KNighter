1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(PossiblyNullPtrMap, const MemRegion*, bool)
  - Tracks pointers that may be NULL and are not yet checked.
  - Value true means “possibly NULL and unchecked”; false means “checked (non-NULL)”.

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer aliases created by assignments/copies.
  - Always resolve through this map to find the ultimate base region to query/update in PossiblyNullPtrMap.

- Helper: resolveRoot(const MemRegion* R, ProgramStateRef S)
  - Follow PtrAliasMap chain to the ultimate base region (guard against cycles).
  - Always use root when reading/writing PossiblyNullPtrMap.

2) Known nullable-return helper

- Implement isKnownNullableGetter(const CallEvent &Call):
  - Return true when the callee name is "mt76_connac_get_he_phy_cap".
  - (Optionally, keep a small string list in case more getters appear.)

3) checkPostCall

- Purpose: mark return values from known capability getters as possibly NULL (unchecked).
- Steps:
  - If isKnownNullableGetter(Call) is true:
    - Obtain the region representing the call’s return using getMemRegionFromExpr(Call.getOriginExpr(), C).
    - If non-null, resolve root and set PossiblyNullPtrMap[root] = true.
  - Do nothing for other calls.

4) checkBind

- Purpose: track pointer aliasing and propagate possibly-null status.
- Steps:
  - Only handle pointer-typed bindings:
    - Obtain LHS region (Loc) with getAsRegion() from Loc; obtain RHS region from Val (getAsRegion()).
    - If both regions exist:
      - Update PtrAliasMap[LHSroot] = RHSroot (use resolveRoot for both ends).
      - If RHSroot is in PossiblyNullPtrMap, copy its boolean to LHSroot (i.e., set PossiblyNullPtrMap[LHSroot] = PossiblyNullPtrMap[RHSroot]).
  - If RHS is a concrete null (Val.isZeroConstant()) and LHS is a region, it is safe to set PossiblyNullPtrMap[LHSroot] = true (still “unchecked”), since it models that LHS may be NULL without a check.

5) checkBranchCondition

- Purpose: mark a pointer as “checked” when the condition tests it against NULL (or truthiness).
- Steps:
  - Strip parens/implicit casts from Condition.
  - Recognize these forms and extract the tested pointer expression Eptr:
    - if (ptr) or if (!ptr):
      - UnaryOperator with opcode UO_LNot -> Eptr is subexpr.
      - Bare DeclRefExpr/MemberExpr/ImplicitCastExpr -> Eptr is the expression itself.
    - if (ptr == NULL) or if (ptr != NULL):
      - BinaryOperator with op == or !=; detect which side is NULL:
        - Use EvaluateExprToInt on each side; if result == 0, treat that side as NULL.
        - Alternatively, fall back to ExprHasName(side, "NULL", C) for macro NULL.
      - Eptr is the non-NULL side.
  - From Eptr, get its region via getMemRegionFromExpr(Eptr, C).
  - If region exists:
    - resolve root.
    - Mark PossiblyNullPtrMap[root] = false (checked).
    - Also consider propagating to direct aliases: iterate PtrAliasMap entries where value equals root and set those to false as well (optional but helpful).

6) checkPreStmt for MemberExpr

- Purpose: detect dereference via “->” on a pointer that may be NULL and is not checked.
- Steps:
  - Implement checkPreStmt(const MemberExpr *ME, CheckerContext &C).
  - If ME->isArrow() is false, ignore.
  - Get the base expression: const Expr *Base = ME->getBase();
  - Get its region: const MemRegion *R = getMemRegionFromExpr(Base, C).
  - If no region, return.
  - Resolve root = resolveRoot(R, State).
  - Query PossiblyNullPtrMap[root]:
    - If found and true (unchecked), report a bug at ME:
      - Generate a non-fatal error node and emit a PathSensitiveBugReport with message:
        - "Possible NULL dereference of capability pointer (mt76_connac_get_he_phy_cap)"
      - Add ME->getSourceRange() as the report range.
    - Otherwise, do nothing.

7) checkPreStmt for UnaryOperator (optional but recommended)

- Purpose: catch other pointer dereferences via “*ptr”.
- Steps:
  - Implement checkPreStmt(const UnaryOperator *UO, CheckerContext &C).
  - If UO->getOpcode() != UO_Deref, ignore.
  - Get subexpr region via getMemRegionFromExpr(UO->getSubExpr(), C).
  - Resolve root; query PossiblyNullPtrMap[root] and report as in step 6.

8) Additional considerations

- When a pointer is compared to NULL (BranchCondition) and then there is a return on the NULL branch, CSA will path-split; even if we simply mark “checked” without distinguishing true/false branches, usual patterns like “if (!p) return; p->...” will be marked as checked before the dereference along the non-NULL path, preventing false positives.
- Keep the checker focused and simple: only flag dereferences of pointers originating from the known nullable capability getter. This minimizes noise.

9) Bug report

- Use std::make_unique<PathSensitiveBugReport> with a short message:
  - "Possible NULL dereference of capability pointer (mt76_connac_get_he_phy_cap)"
- Anchor the report at the MemberExpr (or UnaryOperator) that dereferences the pointer.

10) Summary of callbacks used and their roles

- checkPostCall: identify and tag possibly-null return values from mt76_connac_get_he_phy_cap.
- checkBind: maintain aliasing and propagate possibly-null flag.
- checkBranchCondition: mark pointers as checked when a NULL-check is observed.
- checkPreStmt<MemberExpr>: detect “->” dereference on unchecked possibly-null pointers and report.
- checkPreStmt<UnaryOperator>: detect “*ptr” dereference on unchecked possibly-null pointers and report.
