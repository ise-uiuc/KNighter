1) Program state

- Define three program-state containers to track the “device-provided length” variable and its validation status.
  - REGISTER_MAP_WITH_PROGRAMSTATE(DevLenKindMap, const MemRegion*, unsigned)
    - Purpose: classify tracked variables by a small enum “Kind”.
    - Use Kind = 1 for RSS_KEY_SIZE (rss_max_key_size).
  - REGISTER_MAP_WITH_PROGRAMSTATE(DevLenCheckedMap, const MemRegion*, bool)
    - Purpose: whether the length has been validated against the driver’s maximum.
  - REGISTER_MAP_WITH_PROGRAMSTATE(DevLenOriginSite, const MemRegion*, const Stmt*)
    - Purpose: remember where we first saw the assignment (for better bug location).

- No pointer-alias map is needed for this checker because we will target the well-known field (vi->rss_key_size) directly and look for a matching validation in the same function.

2) Callback selection and implementation details

Step A: Detect the device length assignment from virtio config
- Callback: checkBind
- Goal: find and record when a value is read from virtio_cread8(..., offsetof(..., rss_max_key_size)) into a variable/field (e.g., vi->rss_key_size).

Implementation details:
- In checkBind(Loc, Val, S, C):
  - Using findSpecificTypeInChildren<const CallExpr>(S), check whether the RHS is a call expression.
  - If true, analyze the call expression text with ExprHasName:
    - Require both:
      - ExprHasName(CallExpr, "virtio_cread8")
      - ExprHasName(CallExpr, "rss_max_key_size")
    - Optionally also ensure we are inside the function named “virtnet_probe” (using C.getCurrentAnalysisDeclContext()->getDecl()->getAsFunction()->getNameAsString()) to reduce false positives.
  - Extract the LHS memory region:
    - From the bind destination S, find the LHS expression (e.g., via findSpecificTypeInChildren<const BinaryOperator>(S) and then get LHS) or directly through the “Loc” argument if it is a location for an lvalue.
    - Use getMemRegionFromExpr(LHS, C) to get the MemRegion.
  - If the region is valid, set:
    - DevLenKindMap[Region] = 1 (RSS_KEY_SIZE)
    - DevLenCheckedMap[Region] = false
    - DevLenOriginSite[Region] = S
  - Add the updated state via C.addTransition(State).

Step B: Detect the presence of a correctness check (<= MAX) in conditions
- Callback: checkBranchCondition
- Goal: consider the length “validated” if the function contains a condition that compares this variable to VIRTIO_NET_RSS_MAX_KEY_SIZE.

Implementation details:
- In checkBranchCondition(const Stmt *Condition, CheckerContext &C):
  - If the condition source contains both:
    - "rss_key_size"
    - "VIRTIO_NET_RSS_MAX_KEY_SIZE"
    - using ExprHasName(Condition, ...) checks.
  - If so, mark all DevLenKindMap entries of Kind == RSS_KEY_SIZE as checked.
    - Retrieve the DevLenKindMap via State->get<DevLenKindMap>() and iterate.
    - For each Region with Kind == RSS_KEY_SIZE, set DevLenCheckedMap[Region] = true.
    - Transition to the updated state.
- Optional improvement (if you want to be more precise):
  - Try to extract the specific MemRegion of the variable used in the condition:
    - Use getMemRegionFromExpr on the sub-expression that refers to the variable (MemberExpr/DeclRefExpr).
    - If the region is tracked in DevLenKindMap and Kind == RSS_KEY_SIZE, set only that region to checked.
- Optional improvement 2 (alternative “min/clamp” style validation):
  - In checkPostCall, if you see a call to min/min_t/clamp/clamp_t whose source text includes both "rss_key_size" and "VIRTIO_NET_RSS_MAX_KEY_SIZE", and the result is assigned back to the same LHS region tracked in DevLenKindMap, then mark DevLenCheckedMap[Region] = true.

Step C: Accept constraint-based validation (optional)
- Callback: checkBranchCondition or evalAssume
- Goal: be robust if users write comparisons other than direct textual check.

Implementation details:
- After detecting a comparison involving the tracked symbol, you can use inferSymbolMaxVal(Sym, C) to see if the analyzer already constrained the symbol to be ≤ VIRTIO_NET_RSS_MAX_KEY_SIZE.
- If inferred max value exists and is ≤ MAX, mark checked.
- This is optional; the textual check in Step B is sufficient for this pattern.

Step D: Report if no validation was found by the end of the function
- Callback: checkEndFunction
- Goal: if any tracked RSS_KEY_SIZE variable remains unchecked by function end, report a bug.

Implementation details:
- In checkEndFunction(..., Ctx):
  - Retrieve DevLenKindMap and DevLenCheckedMap.
  - For every Region where Kind == RSS_KEY_SIZE and DevLenCheckedMap[Region] == false:
    - Create a non-fatal error node with Ctx.generateNonFatalErrorNode().
    - Use the statement saved in DevLenOriginSite[Region] as the “interesting location”.
    - Emit a PathSensitiveBugReport with a short message, e.g.:
      - "Device length rss_max_key_size is not validated against VIRTIO_NET_RSS_MAX_KEY_SIZE."
    - Mark the region and the origin statement as “interesting” in the bug report.
  - Do not forget to add a transition if you updated the state.

3) Notes to keep it simple and precise

- Focus on the specific pattern:
  - The read function: virtio_cread8
  - The device field: rss_max_key_size
  - The in-function variable/field: vi->rss_key_size (though the checker only needs the MemRegion of the LHS, not the exact name).
  - The max macro: VIRTIO_NET_RSS_MAX_KEY_SIZE
- Prefer in-function validation detection:
  - If you see a branch condition with both “rss_key_size” and “VIRTIO_NET_RSS_MAX_KEY_SIZE”, treat it as validated.
  - Optionally accept min/min_t/clamp style checks as validation in checkPostCall via ExprHasName on the call expression.
- Keep scope tight (optional but recommended):
  - Only run the logic in functions whose name contains “virtnet_probe” to minimize false positives. You can guard each step with a function-name check.
- No need for alias tracking or interprocedural propagation for this pattern—the patch’s fix is local in virtnet_probe.

4) Bug report message

- Short and clear:
  - Title: “Unvalidated device length used for RSS key”
  - Message: “Device length (rss_max_key_size) not validated against VIRTIO_NET_RSS_MAX_KEY_SIZE.”
- Point to the assignment site (where virtio_cread8 value was bound) as the primary location.
