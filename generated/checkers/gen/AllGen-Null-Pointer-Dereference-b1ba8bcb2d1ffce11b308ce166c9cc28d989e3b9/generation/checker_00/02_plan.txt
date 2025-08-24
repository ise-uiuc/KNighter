Plan

1. Program State
- REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrMap, const MemRegion*, bool)
  - Key: the MemRegion of a pointer returned by an “optional getter”.
  - Value: whether this pointer has been NULL-checked (true = checked, false = unchecked).
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Track pointer aliasing. The value is the canonical source region of the alias. Always resolve to a canonical root before querying OptionalPtrMap.

2. Helper Utilities
- isOptionalGetter(const CallEvent &Call)
  - Return true for known optional getters that may return NULL:
    - "devm_gpiod_get_array_optional"
    - "gpiod_get_array_optional"
    - "devm_gpiod_get_optional"
    - "gpiod_get_optional"
  - Keep the list small and explicit to reduce false positives.
- getCanonical(const MemRegion *R, ProgramStateRef State)
  - Follow PtrAliasMap chains to the canonical root region.
  - Also call R->getBaseRegion() before looking up in maps.
- markOptional(State, const MemRegion *R)
  - R = getCanonical(R).
  - Insert into OptionalPtrMap with false (unchecked).
- setNullChecked(State, const MemRegion *R)
  - R = getCanonical(R).
  - If R is in OptionalPtrMap, set value to true.
  - Also, for any aliases that map to R, set them checked too (iterate PtrAliasMap and update any entries whose root == R; keep it simple).
- isNullChecked(State, const MemRegion *R) -> tri-state
  - R = getCanonical(R).
  - Return OptionalPtrMap lookup (present && true), present && false, or not present.
- getPointerRegionFromExpr(const Expr *E, CheckerContext &C) -> const MemRegion*
  - Use getMemRegionFromExpr(E) (provided).
  - Then canonicalize.
- extractPointerExprFromCondition(const Stmt *Condition) -> const Expr*
  - Detect typical NULL checks and return the pointer expression being tested:
    - UnaryOperator ‘!’: if (!ptr) or if (!!ptr) after unwrapping negations.
    - BinaryOperator ‘==’ or ‘!=’: one side is integer 0/NULL, the other is pointer.
      - Use EvaluateExprToInt to detect 0 on one side; return the other side.
    - Simple truth test: if (ptr) by finding a single DeclRefExpr of pointer type in the condition after IgnoreParenImpCasts.
    - IS_ERR_OR_NULL(ptr) macro: Use ExprHasName(ConditionExpr, "IS_ERR_OR_NULL") and then find the first CallExpr child, its first argument is the pointer expression.
  - Do not treat IS_ERR(ptr) alone as a NULL check.
- isDereferenceStmt(const Stmt *S, CheckerContext &C, const MemRegion *&BasePtrRegion)
  - Try to find a MemberExpr within S where isArrow() is true:
    - If found: Base = M->getBase()->IgnoreParenImpCasts(); R = getPointerRegionFromExpr(Base); if R non-null, set BasePtrRegion=R and return true.
  - Also handle:
    - UnaryOperator ‘*’ with operand O: BasePtrRegion = getPointerRegionFromExpr(O).
    - ArraySubscriptExpr: if the base is a pointer expression (not an array region), BasePtrRegion = getPointerRegionFromExpr(Base).
  - Return true only when a dereference is found and BasePtrRegion is non-null.

3. checkBind (primary seeding and aliasing)
- Purpose:
  - Seed OptionalPtrMap when a variable/field is initialized/assigned with the result of an optional getter.
  - Track pointer aliasing to propagate the “checked” state.
- Implementation:
  - If both Loc and Val are regions (LocR = Loc.getAsRegion(), ValR = Val.getAsRegion()):
    - Record alias: PtrAliasMap[LocR] = getCanonical(ValR). If ValR (canonical) is in OptionalPtrMap, also copy its checked state to LocR (insert OptionalPtrMap[LocR] = OptionalPtrMap[ValR]).
  - Identify when RHS originates from an optional getter:
    - From S (the Stmt causing bind), find a CallExpr child via findSpecificTypeInChildren<CallExpr>(S). If found and isOptionalGetter(Callee), then:
      - Obtain LHS region via Loc.getAsRegion() (canonicalize).
      - markOptional(State, LHSRegion) with false (unchecked).
  - Do not remove or overwrite existing OptionalPtrMap entries unless explicitly overwriting the variable with a new value (overwriting is handled by the regular map insert).

4. checkBranchCondition (observe NULL checks)
- Purpose: Mark pointers as NULL-checked when code checks them against NULL, regardless of branch direction (keep it simple and conservative).
- Implementation:
  - From Condition, get the top-level Expr (cast from Stmt if needed).
  - If ExprHasName(ConditionExpr, "IS_ERR_OR_NULL"):
    - Extract the argument pointer expression and call setNullChecked for its region.
    - Return.
  - Call extractPointerExprFromCondition(Condition):
    - If it returns a pointer expression PtrE and this is a NULL check (patterns described above), then:
      - const MemRegion* R = getPointerRegionFromExpr(PtrE, C); if R, then setNullChecked(State, R).
  - Explicitly ignore IS_ERR(ptr)-only checks; do not mark as checked for those (you can detect via ExprHasName(ConditionExpr, "IS_ERR") but not "IS_ERR_OR_NULL").

5. checkLocation (report dereference without NULL check)
- Purpose: Detect dereferences of pointers returned by optional getters that have not been NULL-checked.
- Implementation:
  - Given (Loc, IsLoad, S):
    - If not IsLoad, return.
    - const MemRegion *BaseR = nullptr;
    - If isDereferenceStmt(S, C, BaseR) is true:
      - BaseR = getCanonical(BaseR).
      - Look up in OptionalPtrMap:
        - If BaseR is present and its value is false (unchecked), then:
          - Generate a non-fatal error node and emit a report:
            - Message: "Possible NULL dereference of optional resource; missing NULL check."
            - Location: S (or the MemberExpr node if available).
      - Otherwise, no report.

6. Optional: checkPostCall (not strictly needed)
- Keep the implementation minimal by relying on checkBind to detect the assignment target of optional getters. No need to use checkPostCall.

7. Notes and Simplifications
- Canonicalization:
  - Always canonicalize regions via getBaseRegion() and following PtrAliasMap to ensure consistent lookups.
- Scope:
  - This checker focuses on pointers that originate from known optional getters. It will not warn for general pointers.
  - It recognizes common NULL-check idioms: if (!ptr), if (ptr), if (ptr == NULL), if (ptr != NULL), and IS_ERR_OR_NULL(ptr).
  - IS_ERR(ptr) does not count as a NULL check and will not suppress the warning.
- False positives minimization:
  - Only report when a clear dereference is observed (->, *, array subscript on a pointer base).
  - Only track pointers seeded from the whitelist of optional getters.

8. Bug Reporting
- Create a single BugType for the checker, e.g., "Optional resource NULL dereference".
- Use generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport> with a short message:
  - "Optional getter may return NULL; missing NULL check before dereference."
- Attach a range to the dereference expression (MemberExpr/UnaryOperator/ArraySubscriptExpr) if available.

9. Callbacks Summary
- Implement:
  - checkBind: Seed OptionalPtrMap for optional getters and track aliases.
  - checkBranchCondition: Mark pointers as null-checked when recognized patterns appear.
  - checkLocation: Detect and report dereferences of unchecked optional pointers.
- Not needed:
  - checkPreCall/checkPostCall (unless you want redundancy).
  - Others are unnecessary for this pattern.
