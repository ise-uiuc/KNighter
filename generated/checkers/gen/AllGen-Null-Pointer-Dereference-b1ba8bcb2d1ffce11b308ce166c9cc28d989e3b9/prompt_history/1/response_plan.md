1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrMap, const MemRegion*, unsigned)
  - Tracks pointers returned from optional-getter functions.
  - Value is a bitmask of flags; we only need one flag:
    - 0: not-null-checked yet (default when inserted)
    - 1: has been NULL-checked (Checked)

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks simple aliases between pointer regions.
  - Key: destination region (the LHS being written), Value: source region (the RHS it aliases).
  - Used to propagate “Checked” status and OptionalPtrMap membership to simple aliases.

Notes:
- Keep the modeling simple and local: we only propagate through direct pointer assignments (e.g., p2 = p1; or obj->fld = p1;). We do not need deep transitive closure; one-step propagation plus a shallow alias update in setChecked is enough to catch the target pattern.


2) Helper utilities

Implement small helpers to keep the callbacks concise:

- bool isOptionalGetter(const CallEvent &Call)
  - Return true if:
    - Callee identifier exists, and
    - Name contains “_optional” (FnName.contains("_optional")), and
    - Call.getResultType()->isPointerType() is true.
  - This keeps the checker generic across various resource getters.

- const MemRegion *getRegionFromExpr(const Expr *E, CheckerContext &C)
  - Wrapper over provided getMemRegionFromExpr(E, C).
  - If it returns null for a complex condition, try drilling down:
    - If E is an ImplicitCastExpr/ParenExpr, peel and retry.
    - If E is a MemberExpr or DeclRefExpr, call getMemRegionFromExpr directly on it.
    - As a final fallback in conditions, try findSpecificTypeInChildren<Expr>(E) to locate a DeclRefExpr/MemberExpr and query its region.

- void propagateAlias(ProgramStateRef State, const MemRegion *Dst, const MemRegion *Src, CheckerContext &C)
  - If Src is in OptionalPtrMap, insert Dst into OptionalPtrMap with the same flag (usually 0 initially).
  - Record alias: State = State->set<PtrAliasMap>(Dst, Src).

- ProgramStateRef setChecked(ProgramStateRef State, const MemRegion *R)
  - If R is tracked in OptionalPtrMap, set flag to 1 (Checked).
  - Also check simple aliases:
    - If PtrAliasMap has entries where key (Dst) aliases R (i.e., PtrAliasMap[Dst] == R), set Dst to Checked as well.
    - Optionally, also if R itself is an alias (i.e., PtrAliasMap[R] = Src), set Checked on Src as well (one step in both directions is sufficient).
  - Return updated State.

- bool isNullCheckOfRegion(const Stmt *Cond, const MemRegion *R, CheckerContext &C)
  - Recognize common forms:
    - if (p) or if (!p):
      - Peel ImplicitCastExpr/ParenExpr; if inner is a DeclRefExpr/MemberExpr that maps to R, return true.
      - For !p, still return true (we only care that a NULL-check was performed).
    - if (p == NULL) or (p != NULL):
      - BinaryOperator EQ/NE with one side mapping to R and the other side evaluating to 0 (use EvaluateExprToInt) or ExprHasName(other, "NULL", C).
    - IS_ERR_OR_NULL(p):
      - If ExprHasName(callee side of the condition, "IS_ERR_OR_NULL", C) is true and the argument region maps to R, return true.
  - We do NOT treat IS_ERR(p) as a NULL-check.

- bool isDerefOfTrackedRegion(const Stmt *S, const MemRegion *&OutR, CheckerContext &C)
  - Identify dereferences that require a non-NULL pointer:
    - MemberExpr with isArrow(): base expression evaluates to pointer; obtain region of base via getRegionFromExpr(Base, C); set OutR if tracked.
    - ArraySubscriptExpr: base expression region is pointer; set OutR if tracked.
    - UnaryOperator with opcode UO_Deref (“*p”): subexpr region; set OutR if tracked.
  - Return true and OutR when the region is tracked in OptionalPtrMap and not Checked.


3) Callback: checkPostCall

Goal: Track returns from *_optional() getters.

- If isOptionalGetter(Call) is true:
  - const MemRegion *RetR = Call.getReturnValue().getAsRegion();
  - If RetR != nullptr:
    - Insert RetR into OptionalPtrMap with flag 0 (not-checked).
  - This also supports immediate dereference of call results like devm_gpiod_get_array_optional(...)->ndescs; the conjured return region will be tracked.


4) Callback: checkBind

Goal: Propagate the “optional and unchecked” status across pointer assignments and remember simple aliases.

- Identify pointer-to-pointer bindings:
  - const MemRegion *Dst = Loc.getAsRegion(); // LHS region (VarRegion, FieldRegion, etc.)
  - const MemRegion *Src = Val.getAsRegion(); // RHS region
  - If both exist and the destination type is a pointer:
    - Call propagateAlias(State, Dst, Src, C).
- Do not mark anything “Checked” here. This callback only handles propagation and alias bookkeeping.


5) Callback: checkBranchCondition

Goal: Mark tracked pointers as Checked when a NULL-check is observed.

- For each tracked region R in OptionalPtrMap with flag 0:
  - If isNullCheckOfRegion(Condition, R, C) returns true:
    - State = setChecked(State, R);
    - Ctx.addTransition(State).
- We perform a flow-insensitive “upgrade to Checked when any NULL-check is seen.” This sacrifices some path precision but keeps the checker simple and avoids false positives. It is sufficient for the target bug, which lacks any NULL-check.


6) Callback: checkLocation

Goal: Detect actual dereferences on tracked and unchecked regions.

- On every load/store:
  - Attempt to recognize a dereference site on S using isDerefOfTrackedRegion(S, OutR, C).
  - If true and OutR is in OptionalPtrMap with flag 0:
    - Report a bug:
      - ProgramStateRef ErrSt = C.generateNonFatalErrorNode();
      - If ErrSt is non-null, emit PathSensitiveBugReport with message:
        “Possible NULL dereference of *_optional() result”
      - Attach range at S if available.


7) Callback: checkPreCall

Goal: Detect passing a tracked unchecked pointer to a function known to dereference its parameters.

- Use provided functionKnownToDeref(Call, DerefParams).
- If returns true:
  - For each index I in DerefParams:
    - const Expr *ArgE = Call.getArgExpr(I);
    - const MemRegion *ArgR = getRegionFromExpr(ArgE, C);
    - If ArgR is tracked in OptionalPtrMap with flag 0:
      - Report a bug at the call site:
        “Possible NULL dereference of *_optional() result (argument I)”
- This increases coverage beyond explicit “->”, “*”, “[]” sites.


8) Optional: checkEndFunction

- No special cleanup required; CSA resets state across functions.


9) Reporting details

- Use one short, clear message:
  - At dereference sites: “Possible NULL dereference of *_optional() result”
  - At deref-known calls: “Possible NULL dereference of *_optional() result (argument <idx>)”
- Create reports with:
  - auto N = C.generateNonFatalErrorNode();
  - if (!N) return;
  - auto R = std::make_unique<PathSensitiveBugReport>(BugType, Msg, N);
  - C.emitReport(std::move(R));


10) Coverage notes and rationale

- We mark pointers as “Checked” once any recognizable NULL-check appears in the function, ensuring no false positives when proper checks exist.
- We deliberately do not treat IS_ERR(p) as a NULL-check. IS_ERR_OR_NULL(p) is treated as a NULL-check.
- The checker fires for “->”, “*”, “[]” dereferences or passing to APIs known to dereference pointers.
- We identify optional getters generically by “_optional” in the function name and pointer return type; this matches the kernel pattern of resource getters returning NULL when absent (e.g., devm_gpiod_get_array_optional).
- Aliases are propagated for simple assignments and struct field stores, sufficient to catch the hx8357 pattern (assign to lcd->im_pins, later deref lcd->im_pins->ndescs without a NULL-check).
