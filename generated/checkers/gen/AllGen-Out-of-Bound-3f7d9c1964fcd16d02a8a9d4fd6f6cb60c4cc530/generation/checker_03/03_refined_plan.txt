1) Program State

- REGISTER_MAP_WITH_PROGRAMSTATE(UntrustedLenMap, const MemRegion*, bool)
  - Tracks integer variables/fields that hold the device-provided RSS key length.
  - Value false: untrusted and not yet validated against VIRTIO_NET_RSS_MAX_KEY_SIZE.
  - Value true: validated (bounded).

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks simple aliases of these integer variables (e.g., len = vi->rss_key_size;).
  - Used to propagate the checked/unchecked status across assignments.


2) Callbacks and Core Logic

A. checkBind (capture and propagate “untrusted RSS length”)

- Goal:
  - Identify assignments that load rss_max_key_size from the device.
  - Mark the destination as untrusted (unchecked).
  - Track aliases among integer variables holding the untrusted length.
  - Recognize “checked” rewrites (e.g., min(len, MAX)).

- Implementation:
  - Given (Loc, Val, S, C):
    1) Identify the left-hand side region:
       - const MemRegion *DstR = Loc.getAsRegion(); If null, return.
    2) Extract the RHS expression from S:
       - Use findSpecificTypeInChildren<const CallExpr>(S) to see if RHS contains a call.
       - If RHS contains a call whose callee is virtio_cread8/virtio_cread16/virtio_cread32 AND ExprHasName(RHS, "rss_max_key_size", C):
         - State = State.set<UntrustedLenMap>(DstR, false)  // mark as untrusted and unchecked.
    3) Alias propagation:
       - If the RHS expression denotes another region SrcR (getMemRegionFromExpr(RHS, C)), and that region is in UntrustedLenMap:
         - State = State.set<PtrAliasMap>(DstR, SrcR)
         - Also copy the checked/unchecked boolean from SrcR to DstR: State = State.set<UntrustedLenMap>(DstR, Checked(SrcR))
       - If not found by region, still handle textual propagation:
         - If ExprHasName(RHS, "rss_key_size", C) and any region already tracked for a MemberExpr/DRE in RHS:
           - Treat similarly as above (alias and copy).
    4) Recognize “checked via min()/clamp” idioms:
       - If RHS is a CallExpr with callee name in {"min", "min_t", "clamp", "clamp_t"} AND
         one operand refers to a tracked region and the other contains "VIRTIO_NET_RSS_MAX_KEY_SIZE" via ExprHasName:
         - Mark DstR as checked: State = State.set<UntrustedLenMap>(DstR, true)
       - Otherwise, if RHS is a ConditionalOperator where either branch uses min()/clamp with the macro as above, mark as checked as well.
    5) Overwrite handling:
       - If DstR already in UntrustedLenMap and RHS does not come from device length or alias:
         - Remove DstR from UntrustedLenMap and PtrAliasMap (the variable is no longer the untrusted length).

- Notes:
  - This is intentionally specific to "rss_max_key_size"; we only taint from expressions that read this device field.

B. checkBranchCondition (mark as validated when compared against the maximum macro)

- Goal:
  - Mark an untrusted RSS length as “checked” once it’s compared against VIRTIO_NET_RSS_MAX_KEY_SIZE (<=, <, >=, >).
  - We keep the implementation simple and conservative.

- Implementation:
  - Given (Condition, C):
    1) If not ExprHasName(ConditionExpr, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C), return (we only care about checks involving the macro).
    2) Try to get the MemRegion of the length being compared:
       - For the left and right children of a BinaryOperator (use findSpecificTypeInChildren<BinaryOperator>(Condition) or directly walk children):
         - For each child expr EVar, try getMemRegionFromExpr(EVar, C). If R = non-null and R exists in UntrustedLenMap:
           - Mark as checked: State = State.set<UntrustedLenMap>(R, true)
           - If PtrAliasMap shows aliases pointing to/from R, mark those as checked too.
    3) If getMemRegionFromExpr fails (rvalue), fall back to textual: if ExprHasName(Condition, "rss_key_size", C):
       - Iterate over all entries of UntrustedLenMap you added earlier (store/remember their regions for the current function scope, or simply try to retrieve region from a MemberExpr child of Condition if present) and mark the matching one as checked if present.
  - Simplicity trade-off:
    - We mark as checked regardless of branch direction (this may slightly over-approximate, but is sufficient to prevent OOB usage warnings when a guard exists).

C. checkPreCall (report uses of unvalidated device-provided length)

- Goal:
  - When an untrusted/unchecked length is used as a length argument to common memory-size-using APIs, report a bug.
  - Keep the function list small but relevant.

- Implementation:
  - Given (Call, C):
    1) Filter callee names to known “length-usage” APIs:
       - sg_init_one(sg, buf, buflen)
       - memcpy, memmove, memset, memcpy_toio, memcpy_fromio, strncpy, strscpy (all with length as last param)
       - You can extend this list if needed, but keep it small and focused.
    2) Identify the length parameter index:
       - sg_init_one: index 2
       - memcpy/memmove/memset/strncpy/strscpy/memcpy_toio/memcpy_fromio: index 2
    3) Retrieve the length argument expression ArgLenE = Call.getArgExpr(IdxLen).
       - First try: const MemRegion *R = getMemRegionFromExpr(ArgLenE, C).
         - If R in UntrustedLenMap and value is false (unchecked), report.
       - Otherwise fallback textual:
         - If ExprHasName(ArgLenE, "rss_key_size", C) and there exists a tracked region (any entry in UntrustedLenMap with false), report.
       - Otherwise alias:
         - If R not tracked but PtrAliasMap maps R to Rsrc and Rsrc tracked as unchecked, report.
    4) Report:
       - auto N = C.generateNonFatalErrorNode();
       - Create a bug type (“RSS length out-of-bounds risk”) once and reuse.
       - Emit a PathSensitiveBugReport with message:
         - "Unvalidated device length used for buffer size (RSS key)."
       - Optionally, add a note to the assignment site if you recorded it (not required).

- Notes:
  - We do not need to compute the destination buffer size; we only enforce that the untrusted device length must be validated before being used in size-driven calls.
  - This mirrors the upstream fix that validates rss_key_size against VIRTIO_NET_RSS_MAX_KEY_SIZE early.

D. Optional: checkPostCall (no-op)

- Not strictly necessary; all tracking happens in checkBind and checkPreCall.


3) Heuristics and Edge-Case Handling

- Assignment chains:
  - If a series of assignments propagate the length (len = vi->rss_key_size; size = len;), checkBind’s alias propagation ensures len/size remain tracked and share checked status.

- Validation via guards:
  - Any branch condition containing both the tracked variable and VIRTIO_NET_RSS_MAX_KEY_SIZE marks it checked.
  - Also accept min()/clamp() writes as checked in checkBind.

- Reset on overwrite:
  - If a tracked variable is overwritten by a value not derived from the device length, remove it from tracking maps.

- Macro handling:
  - Use ExprHasName(E, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C) to detect comparisons with the macro per Suggestions.


4) Minimal Utility Use

- Use ExprHasName for:
  - Detecting "rss_max_key_size" at the device read points.
  - Detecting "VIRTIO_NET_RSS_MAX_KEY_SIZE" in bound checks.
  - Fallback detection of "rss_key_size" in length arguments and conditions.

- Use getMemRegionFromExpr to:
  - Identify regions on assignments and comparisons.
  - Lookup tracked/alias regions in maps for precise matching.

- Use findSpecificTypeInChildren to:
  - Pull out CallExpr or BinaryOperator from the binding/condition statement when needed.


5) Summary of Detection Flow

- Source: vi->rss_key_size = virtio_cread8(...rss_max_key_size...) → mark region unchecked.
- Check: if (vi->rss_key_size <= VIRTIO_NET_RSS_MAX_KEY_SIZE) or len = min(vi->rss_key_size, VIRTIO_NET_RSS_MAX_KEY_SIZE) → mark checked.
- Sink: sg_init_one(..., ..., vi->rss_key_size) or memcpy(..., ..., len) where len is tracked unchecked → report:
  - "Unvalidated device length used for buffer size (RSS key)."
