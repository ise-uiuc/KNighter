1. Program State Customization

- ReleasedFieldMap: map the owning-struct pointer region to which inner pointer fields are known to be released by a helper.
  - REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedFieldMap, const MemRegion*, unsigned)
  - Use bit flags for fields we care about. Define BDEV_FILE_BIT = 1u.
  - Meaning: State[R] has bit BDEV_FILE_BIT if the callee released R->bdev_file but the field was not reset to NULL in the current function.

- PtrAliasMap: track simple aliases of struct-pointer variables to canonicalize the “owning object” region across assignments.
  - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Map lhs pointer variable region → canonical base region. When new alias chains are introduced, always map to the root canonical region; maintain a small helper to resolve to root.

2. Helper Tables and Utilities

- Known close helpers (release inner field(s) of the passed struct):
  - Table entry: "btrfs_close_bdev", ParamIdx = 0, FieldMask = BDEV_FILE_BIT

- Known second-use calls (double-release/deref on struct file*):
  - "fput", ParamIdx = 0
  - "filp_close", ParamIdx = 0

- AST/Region helpers:
  - getBaseRegionFromExpr(const Expr* E, CheckerContext& C): returns the MemRegion of a struct-pointer variable for simple lvalues (DeclRefExpr) using getMemRegionFromExpr(E). If E is a MemberExpr base (e.g., device->...), pass the base expr into getMemRegionFromExpr.
  - canonicalizeBase(const MemRegion* R, ProgramStateRef S): Follow PtrAliasMap to return the alias-root region (stop when no mapping).
  - getFieldAccessInfo(const Expr* E): if E is a MemberExpr, return:
    - FieldName = MemberExpr->getMemberDecl()->getName() (as StringRef)
    - BaseRegion = canonicalizeBase(getMemRegionFromExpr(MemberExpr->getBase(), C), State)
    - Also return the FieldBit if FieldName equals "bdev_file" (BDEV_FILE_BIT), else 0.
  - setFieldReleased(State, BaseR, FieldBit): State = State->set<ReleasedFieldMap>(BaseR, State[BaseR] | FieldBit)
  - clearFieldReleased(State, BaseR, FieldBit): State = State->set<ReleasedFieldMap>(BaseR, State[BaseR] & ~FieldBit); if value becomes 0, erase BaseR from map.

3. Callback Selection and Implementation Details

- checkPostCall(const CallEvent &Call, CheckerContext &C)
  - Purpose: mark an inner pointer field as released by a known “close” helper that operates on a parent struct pointer argument.
  - Steps:
    1. Match Call against the Known close helpers table. If not matched, return.
    2. Get the argument expression at the specified ParamIdx (e.g., 0 for btrfs_close_bdev).
    3. BaseR = getBaseRegionFromExpr(ArgE, C); if null, return.
    4. BaseR = canonicalizeBase(BaseR, State).
    5. Set ReleasedFieldMap[BaseR] |= FieldMask (setFieldReleased).
    6. C.addTransition(State).

- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
  - Purpose:
    - Track aliases between struct-pointer variables: p2 = p1;
    - Clear released bit when bdev_file field is written (e.g., device->bdev_file = NULL).
  - Steps:
    1. If Loc is a MemRegionVal RLoc:
       - If RLoc is a VarRegion whose type is a pointer to a struct (e.g., struct btrfs_device*), and Val is a loc::MemRegionVal RV:
         - Update PtrAliasMap[RLoc] = canonicalizeBase(RV.getRegion(), State). This records p2 aliasing p1’s base. If Val is unknown or non-region, skip.
       - Else if RLoc is a FieldRegion:
         - If FieldRegion’s FieldDecl name == "bdev_file":
           - Get BaseR = canonicalizeBase(FieldRegion->getSuperRegion(), State).
           - Clear the released bit for BDEV_FILE_BIT on BaseR (clearFieldReleased).
           - C.addTransition(State).
    2. No other updates required here.

- checkBranchCondition(const Stmt *Condition, CheckerContext &C)
  - Purpose: flag the pattern if the condition is a non-NULL check on a field that was released by a helper (e.g., if (device->bdev_file) or if (device->bdev_file != NULL)).
  - Steps:
    1. Find a MemberExpr inside Condition using findSpecificTypeInChildren<MemberExpr>(Condition). If none, return.
    2. From the MemberExpr, get FieldName and BaseR via getFieldAccessInfo.
    3. If FieldBit == BDEV_FILE_BIT:
       - Look up ReleasedFieldMap[BaseR]; if BDEV_FILE_BIT is set, report a bug:
         - Message: "Stale file* checked after close; set field to NULL after close".
         - Emit report at Condition; create non-fatal error node and PathSensitiveBugReport.
         - Do not clear the bit here (subsequent uses are still problematic).

- checkPreCall(const CallEvent &Call, CheckerContext &C)
  - Purpose: detect second use (double fput/close) of the already-released bdev_file field.
  - Steps:
    1. If callee is one of Known second-use functions ("fput", "filp_close"), get its pointer argument at index 0.
    2. If the argument expression is a MemberExpr:
       - Extract BaseR and FieldBit via getFieldAccessInfo.
       - If FieldBit == BDEV_FILE_BIT and ReleasedFieldMap[BaseR] has BDEV_FILE_BIT:
         - Report: "Double close/fput on freed struct file* field".
         - Emit bug at the call site (PathSensitiveBugReport).
    3. Otherwise, no action.

- checkRegionChanges(...)
  - Purpose: hygiene. If regions get invalidated (e.g., scope end, unknown writes), drop related state.
  - Steps:
    1. For every region in Regions (or ExplicitRegions), if it’s a VarRegion or a super region that may be the base of our ReleasedFieldMap keys, remove ReleasedFieldMap entry keyed by that base or any alias whose root is that base.
    2. For simplicity, it is acceptable to skip deep cleanup and rely on path sensitivity in this checker; optional.

- checkEndFunction(...)
  - Optional: No special handling required; the analyzer cleans up function-local states automatically. You can leave as no-op.

4. Reporting

- Create a single BugType, e.g., "Stale struct file* field use".
- Reports:
  - On branch condition: "Stale file* checked after close; set field to NULL after close"
  - On second-use call: "Double close/fput on freed struct file* field"
- Use std::make_unique<PathSensitiveBugReport>. Create a non-fatal error node via generateNonFatalErrorNode and emit the report.

5. Notes and Scope

- Field identification: This checker targets the specific field name "bdev_file". Extendable by adding more names and corresponding bits if needed.
- Helper recognition: The core mark is from "btrfs_close_bdev(device)"; add more helpers if they are known to release inner file* fields.
- Alias tracking: Only simple pointer variable aliases are tracked (p2 = p1). Complex aliasing is intentionally out of scope to keep the checker simple and robust for the given pattern.
- Field write clearing: Any assignment to device->bdev_file (including "= NULL") clears the released mark, which mirrors the intended fix of setting it to NULL after closing.
