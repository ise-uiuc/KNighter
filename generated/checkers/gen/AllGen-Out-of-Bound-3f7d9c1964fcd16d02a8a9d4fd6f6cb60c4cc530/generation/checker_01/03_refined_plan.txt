1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(DeviceLenMap, const MemRegion*, bool)
  - Tracks “device-provided length” regions and whether they have been validated.
  - Key: MemRegion of the integer/field storing the length (e.g., vi->rss_key_size).
  - Value: false = unvalidated, true = validated (checked against the protocol-defined max).

- Optional (only if you need simple scalar aliasing):
  - We will not create a separate alias map. Instead, we will propagate the DeviceLenMap entry in checkBind when a value is assigned from a tracked source to a new destination (see Step 4). This keeps the state simple.

2) Callback functions and how to implement them

Step A — Mark device-provided size as “unvalidated” right after reading from device
- Use: checkPostCall
- Goal: Detect reads of rss_max_key_size (or hash key length) via virtio_cread8/16/32 and taint the returned value as “unvalidated device length.”

Implementation details:
- Identify calls by callee name:
  - virtio_cread8, virtio_cread16, virtio_cread32
- Confirm the call reads the relevant field:
  - Inspect the 2nd argument (the offset expression).
  - If ExprHasName(offsetExpr, "rss_max_key_size") or ExprHasName(offsetExpr, "hash_key_length"), treat it as the target field.
- Find where the function return is stored:
  - Use findSpecificTypeInParents<BinaryOperator>(Call.getOriginExpr()) to find the assignment BO_Assign.
  - Extract the LHS expression of the assignment, and get its MemRegion using getMemRegionFromExpr.
- Update state:
  - State = State->set<DeviceLenMap>(LHSMemRegion, /*Validated=*/false).
  - addTransition(State).

Rationale: This marks variables like vi->rss_key_size as a potentially unsafe value until we see an explicit validation.

Step B — Recognize validation branches and mark the device length as “validated”
- Use: checkBranchCondition
- Goal: Detect if-conditions that validate the device-provided size against the protocol max (e.g., VIRTIO_NET_RSS_MAX_KEY_SIZE) and mark the variable as validated on the safe branch.

Implementation details:
- Extract the condition Stmt; find a BinaryOperator (findSpecificTypeInParents/Children or directly dyn_cast if Condition is a BO).
- We care about comparisons: <, <=, >, >=, ==, != (most common will be <= or >).
- Detect involvement of the tracked variable:
  - For both LHS and RHS of the comparison, check if one side refers to a MemRegion present in DeviceLenMap (use getMemRegionFromExpr).
- Detect the maximum macro:
  - If the opposite side’s expression source contains "VIRTIO_NET_RSS_MAX_KEY_SIZE" via ExprHasName, consider this a validation check.
- Create two branch states and mark validation in the safe branch:
  - For “size <= MAX”: True branch => set<DeviceLenMap>(sizeRegion, true); False branch => keep current mapping.
  - For “size < MAX”: True branch => set true.
  - For “size > MAX”: False branch => set true (safe path is the else branch when the condition is false).
  - For “MAX >= size”: True branch => set true.
  - For “MAX > size”: True branch => set true.
- Emit transitions for both branches with Ctx.addTransition(StateTrue) and Ctx.addTransition(StateFalse).

Rationale: This models the check pattern used in the fix and prevents false positives when proper validation exists.

Step C — Detect unsafe uses of unvalidated device length as a size for memory operations
- Use: checkPreCall
- Goal: When an unvalidated device length is used as a size argument to copy/read/write operations into fixed-size buffers, report a bug.

Implementation details:
- Match calls with a “size” parameter and a destination buffer:
  - memcpy(dst, src, len)       => size index = 2, dst index = 0
  - memmove(dst, src, len)      => size index = 2, dst index = 0
  - virtio_cread_bytes(dev, off, buf, len)  => size index = 3, buf index = 2
  - virtio_cwrite_bytes(dev, off, buf, len) => size index = 3, buf index = 2
  - sg_init_one(sg, buf, len)   => size index = 2, buf index = 1
- Get the size expr and attempt to map it to a MemRegion:
  - const MemRegion* LenR = getMemRegionFromExpr(Arg[sizeIndex]);
  - If LenR not in DeviceLenMap, attempt a name-based fallback: if ExprHasName(sizeExpr, "rss_key_size") or "hash_key_length", then treat it as tracked and lookup the region of that expr via getMemRegionFromExpr again (often it already works via LenR).
- If the size region is tracked and DeviceLenMap[LenR] == false (unvalidated):
  - Try to obtain destination buffer’s array size:
    - const MemRegion* BufR = getMemRegionFromExpr(Arg[bufIndex]);
    - If Arg[bufIndex] is an array variable, getArraySizeFromExpr can return the compile-time size (ArraySize).
  - Reporting rule to minimize false positives:
    - If ArraySize is known (i.e., fixed-size array), and size is unvalidated, then report. We don’t need concrete comparison because the bug is using a device-provided length without checking against the max before a bounded copy into a fixed-size array.
- Report:
  - Generate a non-fatal error node using generateNonFatalErrorNode.
  - Create a PathSensitiveBugReport with a short message:
    - “Unvalidated device length used as copy size; check against VIRTIO_NET_RSS_MAX_KEY_SIZE.”
  - Attach the call expression as the location.

Rationale: This targets the actual risky use (copy into fixed-size buffer) and keeps noise low.

Step D — Propagate “device length” taint on simple assignments
- Use: checkBind
- Goal: When the device length is assigned to another scalar (e.g., len = vi->rss_key_size), copy the validation status to the LHS region.

Implementation details:
- The Stmt S in checkBind is the reason for the bind; look for an enclosing BinaryOperator (assignment):
  - const BinaryOperator* BO = findSpecificTypeInParents<BinaryOperator>(S, C);
  - If BO && BO->getOpcode() == BO_Assign:
    - MemRegion* SrcR = getMemRegionFromExpr(BO->getRHS(), C);
    - MemRegion* DstR = getMemRegionFromExpr(BO->getLHS(), C);
    - If SrcR exists in DeviceLenMap, then State = State->set<DeviceLenMap>(DstR, State->get<DeviceLenMap>(SrcR)).
- addTransition(State) if changed.

Rationale: This lets the checker follow common patterns where size is copied to a local before use.

Step E — Optional early warning if no validation appears (conservative)
- Not strictly necessary. To keep the checker precise and simple, we only warn at sinks (Step C). No extra scans for missing checks.

3) Additional matching heuristics to reduce false positives

- Source identification (Step A) is strictly tied to the virtio_cread8/16/32 calls and the specific field names “rss_max_key_size” or “hash_key_length,” using ExprHasName on the offsetof expression. This tightly scopes the checker to the target bug pattern.
- Validation detection (Step B) requires the macro name “VIRTIO_NET_RSS_MAX_KEY_SIZE” to appear in the condition.
- Sink detection (Step C) requires both:
  - The size to be tracked and unvalidated, and
  - The destination buffer to have a compile-time constant array size (getArraySizeFromExpr succeeds).

4) Bug report

- Type: PathSensitiveBugReport
- Message: “Unvalidated device length used as copy size; check against VIRTIO_NET_RSS_MAX_KEY_SIZE.”
- Location: the call site using the unvalidated length as size.
- Only emit once per path at the first risky sink use.

5) Summary of selected CSA hooks

- checkPostCall:
  - Detect virtio_cread8/16/32 reads of rss_max_key_size/hash_key_length, mark LHS as unvalidated in DeviceLenMap.

- checkBranchCondition:
  - Detect comparisons against VIRTIO_NET_RSS_MAX_KEY_SIZE and mark the device length as validated on the safe branch (set DeviceLenMap[region] = true), producing two transitions.

- checkBind:
  - Propagate validation state on simple assignments from a tracked size to another scalar.

- checkPreCall:
  - At memcpy/memmove/virtio_cread_bytes/virtio_cwrite_bytes/sg_init_one, if size arg is tracked unvalidated and destination buffer is a fixed-size array, report a bug.
