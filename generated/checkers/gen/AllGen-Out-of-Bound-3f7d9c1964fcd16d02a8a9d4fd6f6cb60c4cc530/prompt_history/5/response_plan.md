1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(RssKeySizeMap, const MemRegion *, unsigned)
  - Value: 0 = NeedsCheck, 1 = Checked.
  - Tracks integer variables/fields that store rss_max_key_size read from the device and must be validated against VIRTIO_NET_RSS_MAX_KEY_SIZE before use as a length.

No other custom traits/sets are needed.


2) Helper checks/utilities

- isVirtioCread8RssKeySize(const CallEvent &Call, CheckerContext &C)
  - Return true if callee identifier is "virtio_cread8" and one of its arguments contains the field name "rss_max_key_size".
  - Implementation detail:
    - Check Call.getCalleeIdentifier()->getName() == "virtio_cread8".
    - Inspect the offset argument expression (typically the 2nd arg) with ExprHasName(Arg, "rss_max_key_size", C).

- getAssignedRegionForCallResult(const CallEvent &Call, CheckerContext &C)
  - From the CallExpr, go up to the parent BinaryOperator '=' using findSpecificTypeInParents<BinaryOperator>.
  - If found, get LHS expression and resolve its MemRegion via getMemRegionFromExpr.
  - Return the region (or null if not found).

- markRegionCheckedIfComparedToMax(const Stmt *Cond, CheckerContext &C)
  - If condition compares a tracked variable to the macro VIRTIO_NET_RSS_MAX_KEY_SIZE, mark it Checked regardless of comparison direction.
  - Implementation detail:
    - Use findSpecificTypeInChildren<DeclRefExpr>(Cond) to get the primary DRE; resolve its MemRegion; if it exists in RssKeySizeMap with NeedsCheck
    - Also ensure the condition source contains "VIRTIO_NET_RSS_MAX_KEY_SIZE" via ExprHasName(CondExpr, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C).
    - Update the map entry to Checked.

- isKnownLengthUse(const CallEvent &Call, unsigned &LenParamIdx)
  - Return true if Call is one of the known routines that take a length parameter:
    - "memcpy" (len index = 2)
    - "memmove" (len index = 2)
    - "memset" (len index = 2)
    - "sg_init_one" (len index = 2)
  - Populate LenParamIdx accordingly.

- argExprRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C)
  - Return the MemRegion if the argument at Idx reduces to a variable/field region using getMemRegionFromExpr on the argument expression.

- reportUncheckedLengthUse(const Stmt *UseSite, CheckerContext &C, const MemRegion *R)
  - Generate a non-fatal error node and create a PathSensitiveBugReport with a short message:
    - "Device-reported RSS key length is used without validating against VIRTIO_NET_RSS_MAX_KEY_SIZE"
  - Attach the UseSite as the location.


3) Callbacks and logic

- checkPostCall(const CallEvent &Call, CheckerContext &C)
  - Goal: identify assignments from virtio_cread8(... rss_max_key_size) and mark the LHS region as NeedsCheck.
  - Steps:
    - If !isVirtioCread8RssKeySize(Call, C) return.
    - Find the assigned-to region with getAssignedRegionForCallResult(Call, C).
    - If region found, set RssKeySizeMap[region] = NeedsCheck in the state and C.addTransition(newState).

- checkBranchCondition(const Stmt *Condition, CheckerContext &C)
  - Goal: mark the tracked variable as Checked when it is compared with VIRTIO_NET_RSS_MAX_KEY_SIZE.
  - Steps:
    - If ExprHasName(cast<Expr>(Condition), "VIRTIO_NET_RSS_MAX_KEY_SIZE", C) is false, return.
    - Try to resolve the variable used in the condition:
      - Use findSpecificTypeInChildren<DeclRefExpr>(Condition) to get a DRE (common case).
      - If a DRE is found, get its MemRegion.
      - If region exists in RssKeySizeMap with NeedsCheck, update to Checked and transition.
    - Note: Do not attempt to reason about branch direction; any explicit comparison is accepted as a guard.

- checkPreCall(const CallEvent &Call, CheckerContext &C)
  - Goal: detect dangerous use of the unvalidated length as a size argument.
  - Steps:
    - unsigned LenIdx; if (!isKnownLengthUse(Call, LenIdx)) return.
    - const Expr *LenArgE = Call.getArgExpr(LenIdx).
    - Resolve the region: const MemRegion *R = getMemRegionFromExpr(LenArgE, C).
      - If R is null, also try the common case of MemberExpr/DeclRefExpr via IgnoreImplicit/IgnoreParenCasts and re-run getMemRegionFromExpr.
    - If R is in RssKeySizeMap with value NeedsCheck:
      - Report via reportUncheckedLengthUse(Call.getOriginExpr(), C, R).
      - Do not transition the state to Checked; the warning is path-sensitive at the first use without prior guard.

- Optional: checkEndFunction(const ReturnStmt *RS, CheckerContext &C)
  - No specific action needed. The map will be discarded with the function context.


4) Notes and constraints

- This checker is intentionally narrow:
  - It only tracks rss_max_key_size read through virtio_cread8 with an offsetof() argument containing the field name "rss_max_key_size".
  - It requires that the length be assigned to a variable/field (e.g., vi->rss_key_size = virtio_cread8(...)).
  - It considers any comparison with the macro "VIRTIO_NET_RSS_MAX_KEY_SIZE" as a valid check (regardless of direction) to keep the implementation simple and robust to style variations.

- It will warn on calls where the unvalidated variable is used as the length parameter of common memory/sg helpers (memcpy, memmove, memset, sg_init_one). This models the “set/read hash key” pattern where the device-provided length sizes an operation on a fixed-size buffer.

- Utilities used:
  - findSpecificTypeInParents to get the assignment LHS.
  - getMemRegionFromExpr to resolve tracked variables/fields.
  - ExprHasName to detect both the offsetof field "rss_max_key_size" and the max macro "VIRTIO_NET_RSS_MAX_KEY_SIZE" in conditions.
