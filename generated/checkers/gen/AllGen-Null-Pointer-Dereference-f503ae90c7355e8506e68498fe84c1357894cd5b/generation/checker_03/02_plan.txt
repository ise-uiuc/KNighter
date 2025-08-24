Plan: Detect dereferencing a capability pointer returned by a getter that may be NULL (e.g., mt76_connac_get_he_phy_cap) before validating it

1. Program state
- Use a simple state map to track pointers that originate from possibly-NULL getters and whether they have been checked:
  - REGISTER_MAP_WITH_PROGRAMSTATE(NullCkMap, const MemRegion*, bool)
    - Value false: result originates from a possibly-NULL getter and has not been checked.
    - Value true: the pointer (or an alias) has been checked in some condition.
- Track basic aliasing so that checks or uses propagate:
  - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
    - Maps a pointer region to its “root/source” region (the original getter result). If a pointer is assigned from another pointer, link the destination to the source so their “checked” state is shared.
- Helper: findRootAlias(State, R)
  - Follow PtrAliasMap links until no mapping exists; return the canonical root region to be used for lookups/updates in NullCkMap.

2. Callbacks and logic

A. checkPostCall (mark possibly-NULL getter results)
- Goal: When a known getter that can return NULL is called, mark its return as unchecked.
- Implementation:
  - Implement isKnownPossiblyNullGetter(const CallEvent &Call):
    - Return true if callee name equals "mt76_connac_get_he_phy_cap".
    - Keep it simple and exact to avoid false positives.
  - If true:
    - Obtain the return expression (Call.getOriginExpr()) and get its MemRegion using getMemRegionFromExpr.
    - If region exists, insert into NullCkMap with value false (unchecked).
    - Clear any PtrAliasMap mapping for this region (make it its own root).

B. checkBind (propagate aliases; detect “&ptr->field” deref)
- Goal 1: Track pointer aliasing p2 = p1.
  - If Loc is a region for a pointer-typed variable and Val is a region (another pointer):
    - Let Rdst be destination region (from Loc) and Rsrc be source region (from Val).
    - Compute SrcRoot = findRootAlias(State, Rsrc).
    - If SrcRoot is in NullCkMap:
      - Set PtrAliasMap[Rdst] = SrcRoot (link destination to source root).
      - If NullCkMap contains Rdst with a different root, overwrite that with SrcRoot.
      - Do not mark as checked here; just propagate the unchecked/checked status from SrcRoot when needed by always querying Root.
- Goal 2: Catch deref via address-of member expression, e.g., ve = &vc->he_cap_elem;
  - The expression does dereference the pointer even if using &.
  - In checkBind, inspect S (the assignment/initialization stmt):
    - Find a UnaryOperator child that is address-of (&).
    - Inside it, find a MemberExpr child with isArrow() true (->).
    - Get the base expression of that MemberExpr and its MemRegion via getMemRegionFromExpr.
    - Resolve Root = findRootAlias(State, BaseRegion).
    - If Root is in NullCkMap with value false (unchecked), report a bug (see Reporting).
  - This complements checkLocation for the case where taking & of a member may not trigger a load.

C. checkLocation (detect deref uses such as p->f, *p, p[i])
- Goal: When a load/store implicitly dereferences a pointer that is known unchecked from a possibly-NULL getter, emit a warning.
- Implementation:
  - Given Loc and S:
    - Try to identify base pointer expressions for common deref patterns in S:
      - MemberExpr with isArrow() true: base expression is the pointer being dereferenced.
      - UnaryOperator with opcode UO_Deref (*p): the subexpr is the pointer.
      - ArraySubscriptExpr p[i]: the base is the pointer.
    - Use findSpecificTypeInChildren<MemberExpr/UnaryOperator/ArraySubscriptExpr>(S) to detect these, preferring MemberExpr(->) if present.
    - Extract the base expression, get its MemRegion via getMemRegionFromExpr.
    - Resolve Root = findRootAlias(State, BaseRegion).
    - If Root exists in NullCkMap with value false (unchecked), emit a report.
  - Optional conservative filter: If there is no tracked region, do nothing; if it’s tracked and checked, do nothing.

D. checkBranchCondition (mark pointers as checked when referenced in a condition)
- Goal: If the code references a tracked pointer in a condition (if (vc), if (vc != NULL), if (!vc), etc.), mark it as checked to reduce false positives afterward.
- Implementation:
  - Given Condition:
    - Find any DeclRefExpr child; get its MemRegion via getMemRegionFromExpr.
    - For each such region:
      - Resolve Root = findRootAlias(State, Region).
      - If Root is in NullCkMap with value false, update that entry to true (checked).
  - Note: This is a conservative heuristic. We don’t attempt to track branch direction; we just mark as checked once a condition references the pointer, which is adequate for catching the immediate “dereference before check” pattern and reducing later false positives.

3. Reporting
- Create a BugType once (e.g., "Possible NULL dereference of capability pointer").
- On detection in checkLocation/checkBind:
  - Generate a non-fatal error node.
  - Emit a PathSensitiveBugReport with a short message:
    - "Dereference of possibly NULL capability pointer returned by mt76_connac_get_he_phy_cap"
  - Optionally, add a note range to the dereferencing expression (MemberExpr/UnaryOperator/ArraySubscriptExpr) to highlight the exact use site.

4. Notes on utilities usage
- Use getMemRegionFromExpr to convert base expressions and call expressions into MemRegion keys for the maps.
- Use findSpecificTypeInChildren to locate MemberExpr/UnaryOperator/ArraySubscriptExpr within S for deref detection.
- For branch condition handling, DeclRefExpr is sufficient; we do not need to resolve NULL constants explicitly.
- No need to customize evalAssume or constraints; keep the checker simple and focused on the immediate pattern.

5. Summary of minimal steps
- Track results of mt76_connac_get_he_phy_cap as unchecked (checkPostCall).
- Propagate pointer aliasing on assignments (checkBind).
- Detect dereferences via:
  - checkLocation for p->f, *p, p[i].
  - checkBind for &p->f.
- Mark pointers as checked when they appear in a branch condition (checkBranchCondition).
- Report when an unchecked pointer is dereferenced.
