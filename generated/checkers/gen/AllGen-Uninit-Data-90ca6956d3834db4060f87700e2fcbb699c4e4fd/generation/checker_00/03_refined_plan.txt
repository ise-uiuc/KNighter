Plan

1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(TrackedAutoCleanup, const VarDecl *, bool)
  - Key: the VarDecl of a local pointer declared with an auto-cleanup attribute using kfree.
  - Value: initialization flag. false = not initialized yet; true = has been assigned a value in this path.
- No alias tracking is needed. We only care if the pointer variable itself got a value before any return/fallthrough.

2. Callback functions and implementation details

- checkPostStmt(const DeclStmt *DS, CheckerContext &C)
  - Goal: Start tracking variables that match the bug pattern at the point of declaration.
  - Steps:
    1. Iterate all declarations in DS; only process VarDecl.
    2. Filter:
       - Local automatic storage (VD->hasLocalStorage()) and not static.
       - Pointer type (VD->getType()->isPointerType()).
       - Has CleanupAttr (VD->hasAttr<CleanupAttr>()).
       - The cleanup function is kfree (from CleanupAttr::getFunctionDecl()->getName() == "kfree"). If getFunctionDecl is unavailable, fallback to obtaining the name text via source (optional).
    3. If the variable has an initializer:
       - If it is any initializer (including non-NULL), consider it initialized and do not track it. The bug pattern specifically concerns uninitialized pointers.
    4. If the variable has no initializer:
       - Insert into TrackedAutoCleanup with value false (uninitialized).
    5. Do not emit any warning here; just start tracking.

- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
  - Goal: Mark tracked variables as initialized when they are assigned.
  - Steps:
    1. If Loc.getAsRegion() is a VarRegion, get the VarDecl* (VR->getDecl()).
    2. Look up this VarDecl in TrackedAutoCleanup. If present, set its value to true (initialized) in the state for the current path.
  - Rationale: Covers assignments like p = kzalloc(...), p = foo, p = NULL, etc.

- checkPostCall(const CallEvent &Call, CheckerContext &C)
  - Goal: Handle indirect initialization via out-parameters where the address of the variable is passed (e.g., func(&p)).
  - Steps:
    1. Iterate arguments of the call. For each argument:
       - If it is a UnaryOperator with opcode UO_AddrOf and its sub-expression is a DeclRefExpr referring to a VarDecl VD.
       - If VD is tracked in TrackedAutoCleanup, conservatively mark it initialized (set to true).
    2. Rationale: In the kernel, out-parameter initialization patterns are common (e.g., foo(&p)). We assume such calls can initialize the pointer and avoid false positives after such calls.

- checkPreStmt(const ReturnStmt *RS, CheckerContext &C)
  - Goal: Report when returning from a function while some tracked auto-cleanup pointers remain uninitialized.
  - Steps:
    1. Retrieve current TrackedAutoCleanup map from the state.
    2. For each entry with value false (still uninitialized), emit a bug report at this ReturnStmt.
       - Message: "Auto-cleanup pointer may be freed uninitialized; initialize to NULL."
       - Attach a note to the VarDecl declaration location to show where it was declared without initialization.
    3. Use generateNonFatalErrorNode and PathSensitiveBugReport.

- checkEndFunction(const ReturnStmt *RS, CheckerContext &C)
  - Goal: Catch fallthrough to end-of-function without an explicit return (the cleanup still triggers).
  - Steps:
    1. Same as checkPreStmt(ReturnStmt): if any tracked variable is still uninitialized at end of function on this path, report.
    2. Use the function end location as the report location, and add a note pointing to the declaration.

3. Additional considerations
- Function/attribute detection:
  - Use VD->hasAttr<CleanupAttr>() and then CleanupAttr::getFunctionDecl()->getIdentifier()->getName() to compare to "kfree".
  - Limit matching to "kfree" to keep the checker precise for this bug pattern.
- Null-initialization detection:
  - We do not need to special-case NULL: any initializer means the variable is initialized. We only track variables declared without any initializer. This aligns with the pattern “type *p __free(kfree);” that must be initialized to NULL but isn’t.
- Scope/paths:
  - This is path-sensitive: if, along a given path, the variable has not been assigned before a return/end, we warn on that path only.
- Reporting:
  - One report per offending variable per return/end-site. Keep the message short and precise as requested.
- Not needed:
  - BranchCondition, evalAssume, evalCall, checkLocation, checkRegionChanges, and alias maps are unnecessary for this pattern and would complicate the checker without benefit.
