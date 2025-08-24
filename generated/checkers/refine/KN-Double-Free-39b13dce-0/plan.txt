Plan to detect “manual cleanup after devm_add_action_or_reset() failure” (double free)

1) Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(DevmRetToActionMap, SymbolRef, ActionInfo)
  - ActionInfo fields:
    - const FunctionDecl *CleanupFD
    - const MemRegion *DataRegion
- REGISTER_SET_WITH_PROGRAMSTATE(ActiveFailureSet, FailureKey)
  - FailureKey fields:
    - const FunctionDecl *CleanupFD
    - const MemRegion *DataRegion
- Rationale:
  - DevmRetToActionMap ties the symbolic return value of devm_add_action_or_reset to the cleanup function and its data argument.
  - ActiveFailureSet marks that along the current path, we are in the “failure branch” (non-zero return) for that specific cleanup+data pair, i.e., the cleanup is already invoked by devm_add_action_or_reset and any manual call is a double cleanup.

2) Callback selection and implementation details

2.1) checkPostCall: record devm_add_action_or_reset calls
- Goal: Capture the cleanup function and data pointer passed into devm_add_action_or_reset and associate them with the call’s symbolic return value.
- Steps:
  - Identify the function:
    - Prefer Call.getCalleeIdentifier()->getName().equals("devm_add_action_or_reset").
    - Fallback if needed: ExprHasName(Call.getOriginExpr()->getCallee(), "devm_add_action_or_reset", C).
  - Ensure at least 3 arguments are present: (dev, cleanup, data).
  - Extract cleanup function decl (CleanupFD):
    - From Arg1 (2nd parameter): strip parens/implicits.
    - If DeclRefExpr to FunctionDecl, record that FunctionDecl.
    - If UnaryOperator ‘&’ over DeclRefExpr to FunctionDecl, record that FunctionDecl.
    - If no direct FunctionDecl is available (e.g., variable func pointer), skip for simplicity.
  - Extract data region (DataRegion):
    - From Arg2 (3rd parameter): use getMemRegionFromExpr(Arg2, C).
    - If null, skip (we need this to match later).
  - Obtain the call return SVal and its SymbolRef:
    - SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
    - If no symbol, skip (constant fold won’t branch as needed).
  - Insert into DevmRetToActionMap: map RetSym -> {CleanupFD, DataRegion}.

2.2) evalAssume: activate the “failure branch” context
- Goal: When the analyzer splits on a branch condition that is exactly the return symbol of a recorded devm_add_action_or_reset(), mark the true branch as the failure path.
- Steps:
  - If Cond is a DefinedSVal with an underlying SymbolRef Sym:
    - Look up Sym in DevmRetToActionMap.
    - If found:
      - If Assumption == true: we are on the non-zero (failure) path.
        - Construct FailureKey {CleanupFD, DataRegion} from ActionInfo.
        - Add FailureKey to ActiveFailureSet in this successor state.
      - If Assumption == false: do not add it (success path).
      - Optionally erase Sym from DevmRetToActionMap in both successor states to avoid stale entries.
- Scope:
  - This handles the two most common code shapes:
    - if (devm_add_action_or_reset(...)) { ... }
    - int ret = devm_add_action_or_reset(...); if (ret) { ... }
  - For simplicity, this plan does not attempt to parse complex conditions such as (ret != 0) or (ret < 0).

2.3) checkPreCall: detect manual cleanup in the failure branch
- Goal: When a function call occurs, if it matches the cleanup function and data tracked in the failure branch, report a bug (double cleanup).
- Steps:
  - Extract current callee FunctionDecl FD:
    - If available via Call.getDecl(), use it.
    - Else try Call.getCalleeIdentifier() name, but only proceed if we have a FunctionDecl (the plan matches only direct calls to the function).
  - If FD is null, skip (we only handle direct function calls).
  - Extract the first argument’s region (assumes signature cleanup(void *data)):
    - If Call.getNumArgs() == 0, skip.
    - const MemRegion *ArgRegion = getMemRegionFromExpr(Call.getArgExpr(0), C).
    - If null, skip.
  - Construct FailureKey K = {FD, ArgRegion}.
  - If K is in ActiveFailureSet:
    - Report a bug, as the cleanup is being explicitly called on the failure path where devm_add_action_or_reset already invoked it.
    - Create a non-fatal error node and emit a PathSensitiveBugReport with a short message:
      - “Manual cleanup after devm_add_action_or_reset() failure (double free).”
    - Optionally, add notes:
      - At the original devm_add_action_or_reset call site: “devm_add_action_or_reset invokes the action on failure.”
      - At the manual cleanup call site: “Explicit cleanup here duplicates the failure cleanup.”

2.4) Optional hygiene
- checkBeginFunction:
  - No special action required; program state maps/sets start empty per path.
- checkEndFunction / checkRegionChanges:
  - Not required for this pattern.

3) Matching details and utilities

- Function name checks:
  - Use Call.getCalleeIdentifier() for devm_add_action_or_reset.
  - Fallback to ExprHasName when needed but prefer identifier-based matching.
- Extracting function decl from the “cleanup” argument:
  - Accept either ‘cleanup’ or ‘&cleanup’ forms.
  - Only proceed when a direct FunctionDecl is obtained; ignore indirect function-pointer variables for simplicity.
- Extracting the data region:
  - Use getMemRegionFromExpr for robust comparison under casts/implicits.

4) Reporting
- Use generateNonFatalErrorNode to create a node.
- Use std::make_unique<PathSensitiveBugReport> with category like “Linux kernel API misuse”.
- Message: “Manual cleanup after devm_add_action_or_reset() failure (double free).”
- Provide the cleanup call as the primary location. Optionally, add a note at the devm_add_action_or_reset() call.

5) Limits and simplifications
- The checker focuses on:
  - Direct if(cond) where cond is the call result or a variable holding the call result used as a boolean.
  - Direct call to the same cleanup function by name, with the same data pointer as first argument.
- It does not attempt to:
  - Parse complex relational conditions (ret != 0, ret < 0).
  - Match cleanup invoked through function-pointer variables or aliases.
  - Track aliasing of the data pointer; it compares regions directly.

This minimal, path-sensitive plan reliably flags the common anti-pattern:
if (devm_add_action_or_reset(dev, cleanup, data)) {
    cleanup(data); // double cleanup
}
