Plan

1) Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarToResMap, const MemRegion*, const MemRegion*)
  - Key: the MemRegion of the local error variable (e.g., “err”) that stores the return code of the last step call.
  - Value: the base MemRegion of the resource “owner” (e.g., the struct pointer ‘sq’) associated with that last step.
- REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarToStepKindMap, const MemRegion*, unsigned)
  - Key: same error variable MemRegion.
  - Value: an enum/int StepKind for the last step, we only need one kind: LateActivationStep (e.g., “set_*_rdy”, “*_ready”, “activate”, “arm”, “enable”). Use 1 for LateActivationStep.

2) Helper utilities
- isLateStepFunctionName(StringRef Name)
  - Return true if Name contains a “late activation” pattern, for example:
    - Name.contains("set_") && (Name.contains("_rdy") || Name.contains("ready"))
    - Or Name.contains("activate") || Name.contains("enable") || Name.contains("arm")
  - Keep this conservative; the minimal required for the target patch is "set_" and ("_rdy" or "ready").
- isHighLevelCloseFuncName(StringRef Name)
  - Return true if Name contains "close" or "free" or "cleanup"
  - Return false if Name.contains("destroy") to avoid warning on proper low-level counterpart.
- const MemRegion* stripToBaseVarRegion(const MemRegion* R)
  - Walk super-region chain until you reach a top-level VarRegion/ParmVarRegion/SymbolicRegion representing a concrete base object.
  - The idea: for an argument like “sq->sqn” (FieldRegion), this returns the “sq” base region. For “sq” directly, it returns “sq”.
- const MemRegion* pickResourceBaseRegionFromCall(const CallEvent &Call, CheckerContext &C)
  - Iterate call arguments from last to first:
    - const Expr* ArgE = Call.getArgExpr(i);
    - Use getMemRegionFromExpr(ArgE, C); if null, continue.
    - Compute Base = stripToBaseVarRegion(Region).
    - Ignore device-like arguments (optional but reduces noise) if ExprHasName(ArgE, "mdev") or ExprHasName(ArgE, "dev") is true.
    - Return the first non-null Base that is not filtered out.
  - If none found, return nullptr.
- const MemRegion* getErrVarRegionFromCond(const Stmt* Cond, CheckerContext &C)
  - Try to find a DeclRefExpr in children: findSpecificTypeInChildren<DeclRefExpr>(Cond).
  - If found and it refers to a VarDecl, obtain the MemRegion via getMemRegionFromExpr(DRE, C).
  - Return the base (stripToBaseVarRegion) of that region (typically the err variable’s VarRegion).
- bool sameBase(const MemRegion* A, const MemRegion* B)
  - Return A == B after applying stripToBaseVarRegion on both.

3) Track the “late step” assignment to the error variable (checkBind)
- When a value is bound to a location, we want to catch the idiom: err = late_step_call(...).
- In checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C):
  - If Loc is not a MemRegionVal -> bail.
  - Extract the LHS region R from Loc; keep only VarRegion/ParmVarRegion (ignore fields).
  - Try to find if this bind is the result of a call:
    - const CallExpr* CE = findSpecificTypeInChildren<CallExpr>(S); if null, bail.
    - From CE, get the callee name (CE->getDirectCallee()->getIdentifier()->getName()) and run isLateStepFunctionName.
    - If not late step, bail.
  - Determine the resource base region used by this late step:
    - Wrap CE into a CallEvent or re-implement argument iteration:
    - For each argument Expr of CE, call getMemRegionFromExpr and stripToBaseVarRegion; pick the first non-null region that isn’t “mdev/dev” by ExprHasName.
    - If none found, bail (we need a resource to compare later).
  - Update program state:
    - ErrVarToResMap[R] = ResourceBase.
    - ErrVarToStepKindMap[R] = LateActivationStep (1).
  - Do not report here.

4) Detect high-level close/free called in the late-step error branch (checkPreCall)
- Goal: When a call to a high-level “close/free/cleanup” happens under an if-condition that checks the late step’s error variable, and the resource matches, report.
- In checkPreCall(const CallEvent &Call, CheckerContext &C):
  - Get callee name and apply isHighLevelCloseFuncName; if false, return.
  - Find the base resource region used by this cleanup call:
    - BaseCleanup = pickResourceBaseRegionFromCall(Call, C); if null, return.
  - Find enclosing IfStmt:
    - const CallExpr* Origin = dyn_cast_or_null<CallExpr>(Call.getOriginExpr()); if null, return.
    - const IfStmt* If = findSpecificTypeInParents<IfStmt>(Origin, C); if null, return.
  - Extract error-variable region from If condition:
    - ErrVarR = getErrVarRegionFromCond(If->getCond(), C); if null, return.
  - Consult state maps:
    - Look up ErrVarR in ErrVarToResMap and ErrVarToStepKindMap.
    - If not found or StepKind != LateActivationStep, return.
  - Compare resources:
    - If !sameBase(BaseCleanup, ResBaseFromMap), return.
  - Report bug:
    - Create a non-fatal error node and emit PathSensitiveBugReport:
      - Message: "High-level close/free on late-step failure may double free; call destroy_* instead."
      - Location: the cleanup CallExpr.
- Rationale: This matches the target patch scenario where, after hws_send_ring_set_sq_rdy(...) fails (late step), the code calls hws_send_ring_close_sq(sq) instead of the precise destroy function for that last successful step, causing double-free later.

5) Optional refinements to reduce noise
- Only consider IfStmt conditions where the DeclRefExpr type is integer and named like err/ret/rc/status (use ExprHasName on the condition to check common names). This is optional; basic approach already works.
- Exclude cases where the cleanup function name contains "destroy" to avoid flagging correct teardown.
- Clear mappings when entering a new function (not strictly needed; the analyzer state is path-sensitive and scoped).

6) Chosen callbacks and their roles
- checkBind:
  - Detect patterns of “err = late_step_call(...)”.
  - Record mapping from the error variable to the resource base region and mark step kind as LateActivationStep.
- checkPreCall:
  - Identify high-level cleanup calls (“close/free/cleanup”).
  - Verify they are inside an If that checks the previously recorded error variable from a late step.
  - Confirm the resource base region matches between the late step and the cleanup call.
  - Emit a report when matched.
- (No need to use other callbacks. We purposely avoid heavy modeling and keep the implementation simple and targeted to this bug pattern.)

7) Use of provided utilities
- findSpecificTypeInParents to get the enclosing IfStmt of the cleanup call.
- findSpecificTypeInChildren to detect when a bind originates from a CallExpr (in checkBind).
- getMemRegionFromExpr to get regions for call arguments and the condition variable; use region super-chain to get a common base region.
- ExprHasName to skip common device parameters (e.g., "mdev", "dev") in argument scanning and for optional heuristics in conditions.

8) Report message
- Keep it short and clear:
  - "High-level close/free on late-step failure may double free; call destroy_* instead."
