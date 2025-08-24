Plan

1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(CloseNeedsNullMap, const VarDecl*, unsigned)
  - Key: the VarDecl* of the struct pointer variable that is closed (e.g., “device” in btrfs_close_one_device).
  - Value: a 2-bit mask indicating which members must be set to NULL after close:
    - BIT_BDEV = 0x1
    - BIT_BDEV_FILE = 0x2
- REGISTER_MAP_WITH_PROGRAMSTATE(CloseOriginMap, const VarDecl*, const Stmt*)
  - Records the Stmt* where the “close” was observed, to anchor diagnostics.

Rationale: We only need to track, within the same function, which struct pointer variables were passed to a specific close API and which of their members must be NULLed afterward. Tracking by VarDecl is the simplest and robust enough for this pattern (no heavy aliasing needed for this case).

2. Helper utilities
- bool isBtrfsCloseBdev(const CallEvent &Call):
  - Return true if callee name equals "btrfs_close_bdev" (or contains "close_bdev" if you want a slightly broader match).
- const VarDecl* getBaseVarDeclOfExpr(const Expr *E):
  - If E is DeclRefExpr, return E->getDecl() as VarDecl if applicable.
  - Else if E is MemberExpr with isArrow(), check ME->getBase()->IgnoreParenImpCasts(). If it’s a DeclRefExpr, return the VarDecl.
  - Else, attempt findSpecificTypeInChildren<DeclRefExpr>(E) and return the VarDecl from it.
  - Return nullptr if not found.
- bool isNullSVal(SVal V):
  - Return true if V is a DefinedOrUnknownSVal and represents a null/zero constant. If not obvious from SVal, in checkBind use the assignment stmt’s RHS and EvaluateExprToInt to see whether it is 0.
- Optional: StringRef getFieldNameFromMemberStmt(const Stmt *S):
  - Use findSpecificTypeInChildren<MemberExpr>(S) to find the LHS member in an assignment, then return FieldDecl->getNameAsString().

3. checkPostCall
- Purpose: mark that after calling the close routine on a struct pointer, specific members must be set to NULL.
- Steps:
  - If !isBtrfsCloseBdev(Call), return.
  - Extract argument 0 expression (the closed object).
  - Get VarDecl* VD = getBaseVarDeclOfExpr(Arg0Expr). If nullptr, return (we only handle simple cases).
  - State = State->set<CloseNeedsNullMap>(VD, BIT_BDEV | BIT_BDEV_FILE).
  - State = State->set<CloseOriginMap>(VD, Call.getOriginExpr() or Call.getStmt()).
  - C.addTransition(State).

4. checkBind
- Purpose: detect assignments that set the relevant members to NULL, and clear the corresponding bits.
- Trigger: Called when a value is bound to a location (i.e., an assignment or initialization).
- Steps:
  - Extract the bound location region: if it is a FieldRegion, get the FieldDecl* FD and the parent/base expression from the Stmt:
    - Retrieve the assignment statement (BinaryOperator) or the enclosing Stmt via findSpecificTypeInChildren<MemberExpr>(S). Let ME be the member on the LHS.
    - Field name: FD->getNameAsString() (from ME->getMemberDecl()).
    - Base VarDecl: getBaseVarDeclOfExpr(ME->getBase()).
  - If Base VarDecl is tracked in CloseNeedsNullMap:
    - Determine if the assigned value is NULL:
      - Prefer checking SVal Val via isNullSVal(Val).
      - If inconclusive, and if Stmt is BinaryOperator BO, try EvaluateExprToInt on BO->getRHS(); 0 means NULL.
    - If assigned to NULL and field name is "bdev", clear BIT_BDEV.
    - If assigned to NULL and field name is "bdev_file", clear BIT_BDEV_FILE.
    - If both bits get cleared, erase VD from CloseNeedsNullMap (also from CloseOriginMap).
    - C.addTransition with updated state if changed.

5. checkPreCall
- Purpose: early detection of immediate UAF-like use after close (if in the same function), e.g., calling fput on a released member pointer that was not reset to NULL or using it as a param to functions known to deref pointers.
- Steps:
  - If callee name equals "fput":
    - Get argument 0 expression and see if it is a MemberExpr. If so get:
      - Field name and base VarDecl.
    - If base VarDecl is in CloseNeedsNullMap and field name is "bdev_file", and BIT_BDEV_FILE is still set:
      - Report: “Use-after-free: ‘<var>->bdev_file’ freed by close, not reset to NULL.”
      - Create error node via generateNonFatalErrorNode and emit a PathSensitiveBugReport, range at the fput argument, with a note pointing to the close site (from CloseOriginMap if present).
  - Optional: use functionKnownToDeref(Call, ...) to flag any known deref call on the tracked released field (“bdev_file”) and report similarly.

6. checkBranchCondition
- Purpose: flag use of the freed member pointer as an “is-open” flag after it was closed and not nulled.
- Steps:
  - Get the Condition Stmt.
  - Find a MemberExpr inside via findSpecificTypeInChildren<MemberExpr>(Condition).
  - If that MemberExpr’s field name is "bdev_file" and its base VarDecl is tracked with BIT_BDEV_FILE still set:
    - Emit a warning: “Freed member ‘bdev_file’ used as open-flag after close; reset it to NULL.”

7. checkEndFunction
- Purpose: report missing NULL reset at the end of the function if a close happened but a required member remained non-NULL.
- Steps:
  - Iterate CloseNeedsNullMap entries.
  - For each VD with BIT_BDEV_FILE still set:
    - Emit a bug report at function end (or better, anchored at CloseOriginMap[VD] if present) with message like:
      - “Member ‘bdev_file’ not set to NULL after close; stale pointer may be used, causing UAF.”
  - Clear the maps for next function automatically by state destruction.

8. Reporting details
- Use a single BugType, e.g., “Stale member pointer after close”.
- Reports:
  - Immediate UAF on fput: short message “Use-after-free of ‘<var>->bdev_file’ after close.”
  - Use as a flag in condition: “Freed ‘bdev_file’ used as open-flag after close.”
  - Missing nullification at function end: “Member ‘bdev_file’ not set to NULL after close.”
- Create PathSensitiveBugReport via std::make_unique<PathSensitiveBugReport> with generateNonFatalErrorNode.
- Where possible, highlight:
  - The close call site (from CloseOriginMap).
  - The assignment to ‘bdev’ (optional note) if it was cleared while ‘bdev_file’ remained uncleared, to guide the fix.

Notes and simplifications
- Scope: The checker targets the concrete pattern in btrfs_close_one_device: after calling btrfs_close_bdev(device), both device->bdev and device->bdev_file are invalidated; clearing only device->bdev and forgetting device->bdev_file is a bug.
- Aliasing: For simplicity, the plan tracks the VarDecl* of the argument passed to close. This is sufficient in the typical kernel style where the parameter name (device) is used throughout the function. If aliasing is present, this plan can be extended with a PtrAliasMap like REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const VarDecl*, llvm::SmallPtrSet<const VarDecl*, 4>) and checkBind to propagate alias relationships—but it’s not necessary for this specific pattern and patch.
- Field detection relies on MemberExpr LHS in assignments and MemberExpr in branch conditions, which matches kernel C style code using -> operator.
- Utility functions used:
  - findSpecificTypeInChildren to retrieve MemberExpr or BinaryOperator from the current statement.
  - EvaluateExprToInt for robust detection of RHS being 0/NULL.
  - functionKnownToDeref to optionally flag dereferencing calls beyond fput.
