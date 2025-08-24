Plan

1) Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(OptionalRetSyms, SymbolRef, bool)
  - Tracks which return-value symbols come from “optional” getters (value is unused).
- REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrRegions, const MemRegion*, bool)
  - Tracks pointer regions (variables, fields, elements) that currently hold a pointer originating from an “optional” getter (value is unused).

Rationale: We first tag the symbolic return value, then propagate that tag to the destination region at bindings (initializations/assignments). We only need to know “originates from optional getter” to decide whether a dereference is unsafe if the value may be NULL.

2) Helper utilities
- isOptionalGetter(const CallEvent &Call)
  - Return true when callee is one of:
    - "devm_gpiod_get_array_optional"
    - "gpiod_get_array_optional"
    - "devm_gpiod_get_optional"
    - "gpiod_get_optional"
    - "fwnode_gpiod_get_optional"
  - Only proceed if the return type is a pointer type (Call.getResultType()->isPointerType()).
- maybeNullOnThisPath(const Expr *E, CheckerContext &C)
  - Let SVal Ptr = C.getState()->getSVal(E, C.getLocationContext()).
  - If Ptr is not a DefinedOrUnknownSVal, return false.
  - Use SValBuilder &SVB = C.getSValBuilder().
  - Compute Eq = SVB.evalEQ(State, Ptr, SVB.makeNull()).
  - If Eq is Unknown, conservatively return true.
  - If State->assume(Eq, true) is non-null (i.e., "Ptr == NULL" is feasible), return true; else false.
- getTrackedRegion(const Expr *E, CheckerContext &C)
  - Use getMemRegionFromExpr(E, C) to get region of E.
- Optionally, for deref sites: find base pointer Expr from a MemberExpr "->" using findSpecificTypeInParents<MemberExpr>(S, C) and then ME->getBase()->IgnoreParenCasts().

3) checkPostCall (mark return symbols of optional getters)
- If isOptionalGetter(Call):
  - Get return value SVal Ret = Call.getReturnValue().
  - If Ret has a SymbolRef (Ret.getAsSymbol()), add it into OptionalRetSyms map.
  - No bug report here; just mark origin.

4) checkBind (propagate origin to the bound region and aliasing)
- Extract destination region:
  - If Loc is a loc::MemRegionVal MR, set DestR = MR->getRegion().
  - If no region, return.
- Determine if RHS Val comes from optional getter origin:
  - Case A: RHS is a symbol and in OptionalRetSyms.
  - Case B: RHS is a loc::MemRegionVal to some region SrcR and SrcR is in OptionalPtrRegions (alias propagation).
- If A or B: add (DestR, true) to OptionalPtrRegions.
- Else: if DestR is present in OptionalPtrRegions and RHS is not tracked, remove DestR from OptionalPtrRegions (overwriting with an unrelated value clears the origin).
- Note: This handles both variable initialization and assignments, including field assignments like lcd->im_pins = ...

5) checkLocation (detect pointer dereference through “->”)
- Trigger: on any load/store. We are interested in derefs such as ptr->field (MemberExpr with isArrow()) and, optionally, array element deref off a pointer base (ArraySubscriptExpr). Keep it simple and focus on MemberExpr “->”.
- From the incoming Stmt* S, try to find the enclosing MemberExpr via findSpecificTypeInParents<MemberExpr>(S, C).
  - If not found, return.
  - If found but not ME->isArrow(), return.
- Let BaseE = ME->getBase()->IgnoreParenCasts().
- Get the base region R = getMemRegionFromExpr(BaseE, C).
  - If R is not in OptionalPtrRegions, return.
- Check potential NULL on this path:
  - If maybeNullOnThisPath(BaseE, C) is true, report a bug:
    - Message: "Possible NULL deref of optional resource"
    - Create a non-fatal error node and a PathSensitiveBugReport.
    - Highlight BaseE source range if available.

Rationale: If only IS_ERR() was checked earlier, the analyzer still allows BaseE to be NULL on the fall-through path; thus we can flag this as a potential NULL deref.

6) checkPreCall (passing optional pointer to a function that dereferences it)
- Before the call:
  - Use functionKnownToDeref(Call, DerefParams) to get indices of parameters that are dereferenced by callee.
  - For each such index i:
    - Let ArgE = Call.getArgExpr(i).
    - Get region R = getMemRegionFromExpr(ArgE, C). If R not in OptionalPtrRegions, continue.
    - If maybeNullOnThisPath(ArgE, C) is true, report:
      - Message: "NULL optional resource passed to a function that dereferences it"
      - Non-fatal error node, PathSensitiveBugReport.
- This catches passing optional pointers (possibly NULL) to known-deref APIs (e.g., where the core will dereference the pointer).

7) Optional: pruning false positives with explicit null checks
- Not required. Path-sensitivity plus maybeNullOnThisPath prevents reports in branches that proved non-NULL. We do not need to explicitly track null-checks or IS_ERR checks in program state.

8) Bug reporting
- Maintain a BugType member (lazy-initialized) like “OptionalResourceNullDeref”.
- Use generateNonFatalErrorNode(C) and create PathSensitiveBugReport with short, clear messages:
  - For deref: "Possible NULL deref of optional resource"
  - For call arg: "NULL optional resource passed to a function that dereferences it"
- Add a source range to the report:
  - For deref: BaseE->getSourceRange()
  - For call arg: ArgE->getSourceRange()

9) Summary of the flow on the target patch
- Post-call to devm_gpiod_get_array_optional marks return symbol as optional-origin.
- Binding to lcd->im_pins records the field region in OptionalPtrRegions.
- Accessing lcd->im_pins->ndescs triggers checkLocation:
  - Base is lcd->im_pins, tracked as optional-origin.
  - maybeNullOnThisPath evaluates true if code only checked IS_ERR() (i.e., NULL still feasible).
  - Emit: "Possible NULL deref of optional resource".
