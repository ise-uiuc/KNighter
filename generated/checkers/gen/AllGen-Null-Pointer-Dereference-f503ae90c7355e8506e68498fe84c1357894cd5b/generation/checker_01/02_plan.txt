Plan

1) Program state

- No complex traits beyond simple sets.
- Register two sets to track “possibly NULL” capability pointers and their aliases:
  - REGISTER_SET_WITH_PROGRAMSTATE(RiskySyms, SymbolRef)
  - REGISTER_SET_WITH_PROGRAMSTATE(RiskyRegions, const MemRegion*)
  Rationale:
  - RiskySyms holds symbols that come directly from known capability helpers (they may be NULL).
  - RiskyRegions holds concrete locations (variables) that received values derived from these risky symbols (aliases), so later dereferences through those variables are caught as well.

2) Known functions and small helpers

- Maintain a small list of helper functions that may return NULL capability pointers:
  - "mt76_connac_get_he_phy_cap"
  (Keep it extensible to add more names if needed.)
- Helper: isCapabilityHelper(const CallEvent &Call)
  - Returns true if Call’s callee identifier matches one of the names above.
- Helper: exprIsRiskyPtr(const Expr *E, CheckerContext &C)
  - Fetch SVal SV = State->getSVal(E, LCtx)
  - If SV has SymbolRef Sym and Sym ∈ RiskySyms => true
  - Else, if getMemRegionFromExpr(E, C) returns MR and MR ∈ RiskyRegions => true
  - Else false
- Helper: ptrMayBeNull(const Expr *E, CheckerContext &C)
  - DefinedOrUnknownSVal PSV = State->getSVal(E, LCtx).castAs<DefinedOrUnknownSVal>()
  - ProgramStateRef NullSt = State->assume(PSV, /*Assumption=*/false)
  - Return true if NullSt != nullptr (NULL is feasible), else false
- Helper: baseExprOfDeref(const Stmt *S)
  - For dereference patterns, extract the base pointer expression:
    - MemberExpr with isArrow(): return ME->getBase()
    - UnaryOperator with opcode UO_Deref: return UO->getSubExpr()
    - ArraySubscriptExpr: return ASE->getBase()
  - Otherwise, return nullptr

3) checkPostCall

Goal: Mark returned pointers from capability helpers as “risky (may be NULL).”

- If isCapabilityHelper(Call) is true:
  - SVal Ret = Call.getReturnValue()
  - If SymbolRef Sym = Ret.getAsSymbol(): add Sym to RiskySyms
  - (Do not add regions here; the return value might be immediately used or assigned. Assignment/aliasing will be handled in checkBind.)

4) checkBind

Goal: Propagate “risky” from RHS to LHS variables (aliases), including cases like ve = &vc->he_cap_elem.

- Get LHS region: if Loc is loc::MemRegionVal, const MemRegion *LHS = Loc.getAsRegion()
- Determine if RHS is risky using multiple cues:
  - If SymbolRef Sym = Val.getAsSymbol() and Sym ∈ RiskySyms -> RHS is risky
  - Else if const MemRegion *RHSR = Val.getAsRegion() and RHSR ∈ RiskyRegions -> RHS is risky
  - Else if RHSR is a FieldRegion (or any region with a super-region derived from a pointer):
    - Let Base = RHSR->getBaseRegion()
    - If Base is a SymbolicRegion, get BaseSym = cast<SymbolicRegion>(Base)->getSymbol()
    - If BaseSym ∈ RiskySyms -> RHS is risky (this covers ve = &vc->he_cap_elem)
- If RHS is risky and LHS is non-null: add LHS to RiskyRegions

Notes:
- This “taint-like” propagation keeps the bookkeeping simple without full alias graphs.
- No need to remove from sets; the core solver uses constraints to decide non-nullness in later dereferences.

5) checkLocation

Goal: Detect dereferences of risky pointers that may be NULL at that point.

- Only act on loads (IsLoad == true).
- Try to identify dereference base:
  - Using S (the Stmt), if it is one of:
    - MemberExpr (ME) with ME->isArrow(): BaseE = ME->getBase()
    - UnaryOperator with deref: BaseE = subexpr
    - ArraySubscriptExpr: BaseE = array/base expr
  - If not one of these, return (we only care about pointer derefs).
- Risk check:
  - If not exprIsRiskyPtr(BaseE, C), return
- Nullability check:
  - If ptrMayBeNull(BaseE, C) is true:
    - Report: “Possible NULL dereference of capability pointer”
  - Else, do nothing (the path proves it non-NULL, e.g., guarded by if (!ptr) return;).

6) checkPreCall

Goal: Also warn when a risky pointer is passed to a function known to dereference its arguments.

- Use functionKnownToDeref(Call, DerefParams) from utilities.
- If false, return.
- For each index i in DerefParams:
  - const Expr *ArgE = Call.getArgExpr(i)
  - If not exprIsRiskyPtr(ArgE, C), continue
  - If ptrMayBeNull(ArgE, C) is true:
    - Report: “Possible NULL dereference of capability pointer passed to function”

7) Reporting

- Use a single BugType (e.g., “Capability NULL deref”) initialized lazily.
- Create a non-fatal error node and emit a short message:
  - For deref sites: “Possible NULL dereference of capability pointer”
  - Optionally include callee name in message when reporting in checkPreCall: “Possible NULL dereference of capability pointer passed to ‘<fn>’”
- Keep reports unique by site; rely on the path constraints to avoid false positives after proper NULL checks.

8) Why this catches the target bug

- The call to mt76_connac_get_he_phy_cap marks its result symbol as risky (checkPostCall).
- The assignment ve = &vc->he_cap_elem is captured in checkBind by recognizing the FieldRegion base symbol (vc) is risky; ve’s region becomes risky too.
- Subsequent uses like ve->phy_cap_info or vc->... are recognized as dereferences (checkLocation). If there was no guarding if (!vc) return; on that path, ptrMayBeNull() is true, so a report is issued.
- If the code adds a NULL check (as in the patch), the solver’s constraints make ptrMayBeNull() false on the dereferencing path, suppressing the warning.
