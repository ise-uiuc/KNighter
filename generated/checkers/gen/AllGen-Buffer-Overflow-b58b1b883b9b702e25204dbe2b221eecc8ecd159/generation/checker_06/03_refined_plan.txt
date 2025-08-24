Plan

1. Program state
- No complex aliasing is required. Track only:
  - Which local variable (key) holds a risky difference “iov_iter length − round_up(...)” and to which iter object it relates.
  - Whether that risky variable has been guarded by a proper comparison before using it to reduce iter->count.
- Declare two maps:
  - REGISTER_MAP_WITH_PROGRAMSTATE(ShortenToIterMap, const MemRegion*, const MemRegion*)
    - Key: MemRegion of the “shorten-like” variable.
    - Value: MemRegion of the iter object (the base region for the iov_iter pointer/struct used to compute the length).
  - REGISTER_MAP_WITH_PROGRAMSTATE(ShortenGuardedMap, const MemRegion*, bool)
    - Key: MemRegion of the “shorten-like” variable.
    - Value: true if a guard was observed on the current path; false or no entry means unguarded.

2. Helper recognition routines (internal utilities)
- isCallNamed(E, "name"): dyn_cast<CallExpr>(E->IgnoreParenCasts()), then check callee identifier. As a fallback or convenience, ExprHasName(E, "name", C).
- isIovIterLenExpr(E, IterRegionOut):
  - True if E is:
    - Call to iov_iter_count(iter): extract argument 0 and set IterRegionOut = getMemRegionFromExpr(arg0, C).
    - MemberExpr like iter->count (field named "count"): base is the iter expr; set IterRegionOut = getMemRegionFromExpr(base, C).
- isRoundUpCall(E): E is call to round_up.
- isIterCountFieldRegion(LocRegion, IterRegion):
  - True if LocRegion is a FieldRegion whose field name is "count" and its super/base region corresponds (or aliases) to IterRegion (pointer deref base region of iter).
- getVarRegionFromExpr(E): getMemRegionFromExpr(E, C) and ensure it’s a VarRegion or equivalent symbol region of a local variable.

3. Detect risky “shorten” computation (checkBind)
- Goal: When a variable gets bound to “iov_iter length − round_up(...)”, record it as risky and remember which iter it belongs to.
- In checkBind(Loc, Val, S, C):
  - Extract the destination region R = Loc.getAsRegion(); ensure it is a variable-like region (local or parameter); call this RShorten.
  - Inspect S (the RHS expression site):
    - Find a BinaryOperator with opcode BO_Sub via findSpecificTypeInChildren<BinaryOperator>(S). If none, return.
    - For that subtraction SubBO:
      - Check LHS is an iov_iter length expression: isIovIterLenExpr(SubBO->getLHS(), IterRegionLHS).
      - Check RHS is a round_up call: isRoundUpCall(SubBO->getRHS()).
      - If both checks succeed:
        - State = State->set<ShortenToIterMap>(RShorten, IterRegionLHS);
        - State = State->set<ShortenGuardedMap>(RShorten, false);
        - C.addTransition(State).
  - Also handle declaration with initializer (e.g., size_t shorten = ...): it comes through checkBind as well, so the same logic applies.

4. Detect presence of a guard (checkBranchCondition)
- Goal: If code contains a guard ensuring “no underflow”, mark the risky variable as guarded.
- In checkBranchCondition(Condition, C):
  - Extract a BinaryOperator BO from Condition if any.
  - Case A: Guard of the form “shorten >= iter->count” (or swapped sides):
    - If either side references a known shorten variable:
      - ShortenRegion = getVarRegionFromExpr(sideExpr).
      - Other side must be MemberExpr "count" of the same iter object: isIovIterLenExpr(otherSide, IterRegionCond) and ensure it’s specifically “iter->count”, not iov_iter_count(); require MemberExpr with field name "count".
      - If ShortenRegion is found in ShortenToIterMap and IterRegionCond matches its IterRegion, mark guarded:
        - State = State->set<ShortenGuardedMap>(ShortenRegion, true);
        - C.addTransition(State).
  - Case B: Guard of the form “round_up(...) <= iov_iter_count(iter)” (or swapped ≥):
    - Detect one side is round_up call, the other side is iov_iter length call (not MemberExpr).
    - Extract IterRegion from the iov_iter length side (isIovIterLenExpr(...)).
    - For all entries in ShortenToIterMap whose IterRegion equals this IterRegion, set ShortenGuardedMap(entryKey) = true.
      - Iterate map using State->get<ShortenToIterMap>(), update those with matching IterRegion, and add transition.

5. Report when subtracting the risky variable from iter->count without guard (checkBind)
- Goal: Warn at the sink where iter->count is reduced by the risky variable and no guard was seen.
- In checkBind(Loc, Val, S, C):
  - If LocRegion is a FieldRegion for "count" (iter->count) and we are performing a subtraction store:
    - Detect two common forms by analyzing S:
      - Compound assign: BinaryOperator BO_SubAssign like “iter->count -= X”.
        - Extract XExpr (RHS), get ShortenRegion = getVarRegionFromExpr(XExpr). If ShortenRegion exists in ShortenToIterMap and ShortenGuardedMap(ShortenRegion) is false (or missing), emit a report.
      - Simple assign with subtraction: “iter->count = iter->count − X”.
        - Find RHS BinaryOperator BO_Sub; locate a variable XExpr inside RHS; ShortenRegion = getVarRegionFromExpr(XExpr). Same checks as above.
    - Additionally confirm that this store applies to the same iter object as recorded:
      - Retrieve IterRegionLHS from LocRegion (base of FieldRegion). Compare to the IterRegion stored in ShortenToIterMap(ShortenRegion). If match and not guarded, it’s a hit.
  - Reporting:
    - Create an error node: auto N = C.generateNonFatalErrorNode();
    - Message: “Possible size_t underflow: subtracting rounded-up length from iov_iter length without guard”.
    - Emit: PathSensitiveBugReport or BasicBugReport with the statement S as the location.
  - After reporting (or regardless to avoid duplicate reports on the same path), clear the entry for ShortenRegion from both maps for this path to reduce duplicate warnings.
    - State = State->remove<ShortenToIterMap>(ShortenRegion);
    - State = State->remove<ShortenGuardedMap>(ShortenRegion);
    - C.addTransition(State).

6. Optional safety refinements
- If the risky variable is subsequently assigned a constant zero before being used (e.g., “shorten = 0;”), treat that as guarded:
  - In checkBind, when binding to a tracked ShortenRegion and RHS is integer literal 0, set ShortenGuardedMap(ShortenRegion) = true.
- Clear per-function state:
  - In checkEndFunction, clear both maps to avoid stale state leaks across functions.

7. Callbacks summary and purpose
- checkBind:
  - Detect and record risky “shorten = iov_iter_count(iter) − round_up(...)”.
  - Detect and warn when storing “iter->count -= shorten” or “iter->count = iter->count − shorten” without guard.
  - Optionally mark guarded when “shorten = 0”.
- checkBranchCondition:
  - Mark “shorten” as guarded if seeing “shorten >= iter->count” test for the same iter.
  - Mark all “shorten” tied to an iter as guarded if seeing “round_up(...) <= iov_iter_count(iter)” for that iter.
- checkEndFunction:
  - Cleanup state (optional, but keeps state minimal).

8. Notes to minimize false positives
- Only track “shorten-like” variables when the subtraction shape exactly matches:
  - LHS is iov_iter_count(iter) or iter->count (MemberExpr “count”).
  - RHS is round_up(...).
- Only warn when the same tracked variable is used to reduce the same iter->count field and no guard has been seen on the current path.
