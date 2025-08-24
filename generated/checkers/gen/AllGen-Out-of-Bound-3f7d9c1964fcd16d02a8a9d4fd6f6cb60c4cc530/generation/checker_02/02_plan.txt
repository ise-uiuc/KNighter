1) Program state

- REGISTER_SET_WITH_PROGRAMSTATE(UncheckedLenSet, const MemRegion*)
  - Tracks struct/variable regions that hold a device-reported RSS key length which has not yet been validated against VIRTIO_NET_RSS_MAX_KEY_SIZE.
  - We will add the region when rss_max_key_size is read from the device and assigned (unvalidated), and remove it when we detect a proper max-bound check.

No other custom traits/maps are needed.


2) Callbacks and how to implement them

A) checkPostCall (mark “device-reported length” as unvalidated)
- Goal: Detect vi->rss_key_size = virtio_cread8(vdev, offsetof(..., rss_max_key_size))
- Steps:
  1. Identify call to virtio_cread8:
     - If Call.getCalleeIdentifier() exists and name equals "virtio_cread8".
  2. Ensure the offset argument corresponds to rss_max_key_size:
     - Let OffArg = Call.getArgExpr(1); if ExprHasName(OffArg, "rss_max_key_size", C) is true, treat it as RSS key size read.
  3. Find the LHS of the assignment:
     - Retrieve the origin expression of the call, E = Call.getOriginExpr().
     - Use findSpecificTypeInParents<BinaryOperator>(E, C) and ensure it’s an assignment operator (isAssignmentOp()).
     - Extract LHS expression from the BinaryOperator.
  4. Obtain the LHS memory region:
     - const MemRegion* LHSReg = getMemRegionFromExpr(LHSExpr, C).
     - If LHSReg is not null, add it to UncheckedLenSet: State->add<UncheckedLenSet>(LHSReg).
  5. Optional (scope restriction): If desired to reduce noise, check enclosing function name equals "virtnet_probe" via C.getLocationContext()->getDecl()->getAsFunction()->getNameAsString() before adding to the set.

Rationale: This marks the field (e.g., vi->rss_key_size) as “device-reported, not yet validated” immediately after reading it from the device.


B) checkBranchCondition (mark as validated when compared to the fixed max)
- Goal: Detect the presence of an explicit bounds check against VIRTIO_NET_RSS_MAX_KEY_SIZE.
- Steps:
  1. Get the branch condition Stmt* Cond.
  2. Try dyn_cast<BinaryOperator>(Cond) (or findSpecificTypeInChildren<BinaryOperator>(Cond) if necessary):
     - If not a BinaryOperator, return.
     - Only consider relational comparisons: >, >=, <, <=, ==, !=.
  3. Extract LHS and RHS expressions.
  4. Determine if one side contains the macro name VIRTIO_NET_RSS_MAX_KEY_SIZE:
     - If ExprHasName(LHS, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C) or ExprHasName(RHS, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C) is true, proceed.
  5. Identify the other side as the “length” expression:
     - Let LenExpr be the non-macro side (LHS if RHS was macro, RHS if LHS was macro).
     - Try to obtain its region: const MemRegion* LenReg = getMemRegionFromExpr(LenExpr, C).
  6. If LenReg is in UncheckedLenSet, remove it:
     - State = State->remove<UncheckedLenSet>(LenReg); C.add_transition(State).
  7. Notes:
     - Accept any comparison operator here (>, >=, <=, <, ==, !=), since presence of comparison against the macro is sufficient evidence of validation for this checker.
     - This is intentionally simple: if the code checks the value against the constant, we consider it validated.

Rationale: The bug fix added a “if (rss_key_size > VIRTIO_NET_RSS_MAX_KEY_SIZE) { …goto free; }” check. Detecting any comparison with the macro is a good proxy that validation exists.


C) checkPreCall (report usage of unvalidated device length)
- Goal: Report when the unvalidated rss_key_size is used as an argument in a call (e.g., for buffer sizing, setting/reading the hash key).
- Steps:
  1. For the current call, iterate all arguments:
     - For each arg expression A:
       - First, try to directly obtain a region: const MemRegion* ArgReg = getMemRegionFromExpr(A, C).
         - If ArgReg is non-null and ArgReg is in UncheckedLenSet, we have a use of an unvalidated device length. Report (see D).
       - If ArgReg is null or not in the set, use a text-based fallback:
         - If ExprHasName(A, "rss_key_size", C) is true, try to resolve the region of the corresponding field by locating a MemberExpr inside A using findSpecificTypeInChildren<MemberExpr>(A) and then getMemRegionFromExpr on that MemberExpr. If that region is in UncheckedLenSet, report.
  2. Optionally, to reduce noise, restrict sinks to known size-taking APIs if desired:
     - For instance, if Call name is "sg_init_one" (3rd argument is size), or other known helper functions that set/read RSS key length. But the general "any call arg uses rss_key_size" is acceptable and simple.
  3. If a report is emitted, do not alter state; multiple reports can occur on different paths, which is acceptable.

Rationale: Using the device-provided length for operations without validation is the dangerous behavior we want to flag.


D) Bug reporting helper
- When a violation is detected in checkPreCall:
  - Use ExplodedNode* N = C.generateNonFatalErrorNode(); if (!N) return;
  - Create a static BugType (e.g., "Unvalidated device length").
  - Build a short message: "rss_max_key_size used without validating against VIRTIO_NET_RSS_MAX_KEY_SIZE".
  - Emit a PathSensitiveBugReport with the current statement as the location.
- Keep the message short and clear as requested.


E) Optional: checkEndFunction
- Not required. We only report at actual uses (sinks). No need to warn on mere presence of unvalidated value if it is never used.


3) Heuristics/Utilities used

- ExprHasName to:
  - Recognize the offset argument containing "rss_max_key_size".
  - Find comparisons to "VIRTIO_NET_RSS_MAX_KEY_SIZE".
  - Fallback detection of argument expressions mentioning "rss_key_size".
- findSpecificTypeInParents<BinaryOperator> to find the assignment receiving virtio_cread8 return.
- findSpecificTypeInChildren<MemberExpr> as a fallback to re-discover the MemberExpr for region retrieval when needed.
- getMemRegionFromExpr to convert LHS and argument expressions into MemRegion for set membership in UncheckedLenSet.

4) Constraints and simplifications

- We assume that explicit textual comparisons to VIRTIO_NET_RSS_MAX_KEY_SIZE in a branch condition indicate proper validation. This keeps the checker simple and matches the patch style.
- We intentionally target the concrete field/macro names:
  - Source: "rss_max_key_size" via virtio_cread8’s offset argument.
  - Validation: "VIRTIO_NET_RSS_MAX_KEY_SIZE".
  - Use: arguments that reference "rss_key_size".
- Alias tracking is not necessary here because the tracked object is a scalar field and we directly look for its usage by name or by region when possible.
- If desired, the checker can be scoped to function "virtnet_probe" to reduce noise; otherwise it works globally for the same pattern.
