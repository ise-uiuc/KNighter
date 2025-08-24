Plan

1) Program state customization
- Register maps/sets:
  - REGISTER_MAP_WITH_PROGRAMSTATE(BaseToReleasedFields, const MemRegion*, FieldSetTy)
    - Key: the MemRegion of the struct pointer variable (the “base” expression like device in device->bdev_file).
    - Value: an ImmutableSet<const FieldDecl*> of member fields currently considered “released/stale” because they have been closed/freed but not set to NULL.
  - REGISTER_SET_WITH_PROGRAMSTATE(FieldSetTy, const FieldDecl*)
    - Set type used as the value type above.
  - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
    - Track simple pointer-to-pointer aliases for struct pointers (so if p2 = p1, we treat p2 and p1 as aliases).
- Rationale:
  - We only need to track whether a specific member field of a specific base pointer was “released” but not set to NULL. We remove the field from the set when we observe base->field = NULL.
  - Minimal alias tracking (pointer variables that point to the same struct) avoids missing obvious renamings within the same function body.

2) Helper tables and utilities
- Known wrapper releasers of a field of a struct parameter:
  - Define a small static table KnownFieldReleasers:
    - { "btrfs_close_bdev", ParamIndex = 0, FieldName = "bdev_file" }
  - This models the pattern where a wrapper (e.g., btrfs_close_bdev(dev)) internally releases a particular member (dev->bdev_file).
- Known direct release functions:
  - For Linux, at least "fput" (Param 0). Also accept "kfree" if you want to generalize, but it’s not necessary for the target bug.
  - For direct release calls, if the argument is a MemberExpr (e.g., fput(dev->bdev_file)), mark that exact field as released.
- Known dereference functions:
  - Reuse functionKnownToDeref(Call, DerefParams) to identify calls that will dereference pointer arguments (if a released field is passed in such positions, it’s a UAF).

- Helper routines you will implement:
  - getBaseVarRegion(const Expr *Base, CheckerContext &C):
    - Return the MemRegion of the base pointer variable (use getMemRegionFromExpr on Base). If that region is an alias in PtrAliasMap, canonicalize it to the root alias (follow until no more mapping).
  - lookupFieldDeclFromPointee(const Expr *Base, StringRef FieldName):
    - From Base->getType()->getPointeeType(), get the RecordDecl, and find the FieldDecl by FieldName. Return nullptr if not found.
  - addReleased(State, BaseRegion, FieldDecl*)
  - removeReleased(State, BaseRegion, FieldDecl*)
  - isReleased(State, BaseRegion, FieldDecl*)
  - resolveAlias(State, R): follow PtrAliasMap to root region.

3) Callback: checkPostCall
- Goal: mark struct fields as “released/stale” after calls that release them.
- Steps:
  1) Get callee name; handle two cases:
     - Wrapper-releasers (KnownFieldReleasers):
       - Identify the specified parameter expression Arg.
       - Compute BaseRegion = getBaseVarRegion(Arg, C).
       - Lookup FieldDecl* FD = lookupFieldDeclFromPointee(Arg, FieldName).
       - If BaseRegion and FD are valid, State' = addReleased(State, BaseRegion, FD).
     - Direct release like fput:
       - Examine the first argument:
         - If it is a MemberExpr ME (possibly behind casts), extract:
           - FD = cast<FieldDecl>(ME->getMemberDecl()).
           - BaseRegion = getBaseVarRegion(ME->getBase(), C).
           - If valid, State' = addReleased(State, BaseRegion, FD).
         - Else if it’s a DeclRefExpr or other expr, you can ignore for this specific checker (we’re targeting struct member fields).
  2) Bind the new state if changed.

4) Callback: checkPostStmt(const BinaryOperator *BO)
- Goal: detect nullification or re-assignment of the released member field and update state.
- Steps:
  - If !BO->isAssignmentOp(), return.
  - Let LHS = BO->getLHS()->IgnoreParenImpCasts().
  - If LHS is a MemberExpr ME:
    - FD = cast<FieldDecl>(ME->getMemberDecl()).
    - BaseRegion = getBaseVarRegion(ME->getBase(), C).
    - If BaseRegion and FD valid:
      - Check RHS = BO->getRHS()->IgnoreParenImpCasts().
      - If RHS is a NULL pointer constant or evaluates to 0 using EvaluateExprToInt:
        - State' = removeReleased(State, BaseRegion, FD).
      - Else:
        - Any non-NULL re-assignment means the old stale pointer is no longer present; conservatively remove the released mark as well:
          - State' = removeReleased(State, BaseRegion, FD).
  - Bind the new state if changed.

5) Callback: checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
- Goal: maintain simple pointer alias relationships for struct pointers.
- Steps:
  - Retrieve the immediate parent statement and see if S is (or has) a BinaryOperator of the form P2 = P1.
  - If both sides are pointer-to-struct types:
    - Get MemRegion for LHS variable and RHS variable (use getMemRegionFromExpr with the corresponding DeclRefExprs).
    - Record alias mapping PtrAliasMap[LHSRegion] = resolveAlias(State, RHSRegion).
    - Do not modify BaseToReleasedFields here; release tracking is keyed by the base-region representative (root alias).

6) Callback: checkPreCall(const CallEvent &Call, CheckerContext &C)
- Goal: detect a suspicious use of a released/stale field as a call argument.
- Steps:
  - For each argument:
    - If the argument Expr is a MemberExpr ME:
      - FD = ME->getMemberDecl(); BaseRegion = getBaseVarRegion(ME->getBase(), C).
      - If isReleased(State, BaseRegion, FD):
        - If the callee is:
          - A release function (e.g., fput): report “Double close/use on stale field”.
          - Or functionKnownToDeref(Call, DerefParams) and current arg index is in DerefParams: report “Use-after-free via dereferenced stale struct member”.
        - Generate a non-fatal error node and emit a short PathSensitiveBugReport.

7) Callback: checkBranchCondition(const Stmt *Cond, CheckerContext &C)
- Goal: detect using a released/stale field in non-NULL tests, which is the pattern leading to a second close/UAF.
- Steps:
  - Inspect Cond for MemberExpr instances:
    - Use findSpecificTypeInChildren<MemberExpr>(Cond) (if multiple, visit all by recursively walking children).
    - For each ME found:
      - FD = ME->getMemberDecl(); BaseRegion = getBaseVarRegion(ME->getBase(), C).
      - If isReleased(State, BaseRegion, FD):
        - If the condition is a nullness check or truthiness test on ME (patterns: ME, ME != NULL, ME == NULL, !ME):
          - Emit a warning: “Stale struct member used in condition; not set to NULL after close”.

8) Callback: checkEndFunction(const ReturnStmt *RS, CheckerContext &C)
- Goal: catch the core pattern even if the later use is outside this function: a function closed a member but did not set it to NULL before exit.
- Steps:
  - Iterate over all entries in BaseToReleasedFields.
  - For each base region with a non-empty set of FD:
    - For each FD still marked as released, emit a warning at the function end:
      - “Field '<name>' released but not set to NULL before function exit.”
  - This catches the exact btrfs_close_one_device pattern: after btrfs_close_bdev(device), device->bdev_file was not set to NULL.

9) Bug report details
- Use generateNonFatalErrorNode() to create an error node.
- Messages (short and clear):
  - “Field '<field>' released but not set to NULL.”
  - “Use-after-free: stale struct member '<field>' used in condition.”
  - “Double close: calling '<callee>' on stale struct member '<field>'.”
- Use std::make_unique<PathSensitiveBugReport>(...) for emission.

10) Notes and simplifications
- Keyed by the base pointer variable’s MemRegion (not the pointee object region) because MemberExpr->getBase() expressions consistently refer back to that base pointer in typical kernel code (device, inode, file, etc.). This keeps the design simple and stable.
- Aliasing: keep it minimal (straightforward p2 = p1 within the same function). Use resolveAlias() to map to a root region.
- Field identification: prefer comparing FieldDecl* (less brittle than string). For wrapper releasers, discover FieldDecl* by name via the pointee’s RecordDecl; for MemberExpr we already have the FD directly.
- False positives reduction:
  - We clear the “released” marker on any subsequent assignment to the member (NULL or non-NULL), because the stale value is no longer present.
  - We primarily warn at usage sites (branch conditions and calls) and at function exit if stale remains.

Callbacks summary
- checkPostCall:
  - Mark a member field as released for:
    - Wrapper: btrfs_close_bdev(dev) => dev->bdev_file marked released.
    - Direct: fput(dev->bdev_file) => mark released.
- checkPostStmt(BinaryOperator):
  - If assigning to a member, remove its released mark when RHS is NULL (or any non-NULL re-assignment).
- checkBind:
  - Record pointer-to-pointer aliases for struct pointers.
- checkPreCall:
  - Warn if a released member is passed to fput (double close) or to a known-deref function (UAF).
- checkBranchCondition:
  - Warn if a released member appears in a nullness/truthiness condition.
- checkEndFunction:
  - Warn if any released member was not set to NULL before exiting the function.
