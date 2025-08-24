Plan

1) Program state

- REGISTER_SET_WITH_PROGRAMSTATE(DeviceSizeSet, const MemRegion*)
  - Purpose: Track variables/fields that hold a device-provided size (rss_max_key_size) so we can recognize their later uses as “untrusted length” values.

- No extra alias map is strictly necessary. We will propagate the tag on simple assignments in checkBind (destination becomes “device-size” if the source is “device-size”).

2) Helper predicates and utilities

- bool isVirtioCreadOfRssKeySize(const CallEvent &Call, CheckerContext &C)
  - Return true if Call is to virtio_cread8, virtio_cread16, or virtio_cread32 and:
    - The 2nd argument (offset) expression source text contains “rss_max_key_size” using ExprHasName.
  - This catches the specific device-provided size field we care about.

- bool isKnownCopyLenSink(const CallEvent &Call, unsigned &DestIdx, unsigned &LenIdx)
  - Recognize and return the destination and length argument indices for known copy-like APIs:
    - memcpy(dest, src, len): DestIdx=0, LenIdx=2
    - memmove(dest, src, len): DestIdx=0, LenIdx=2
    - virtio_cread_bytes(dev, off, buf, len): DestIdx=2, LenIdx=3
  - Extendable if you need more sinks later.

- const MemRegion* resolveExprRegion(const Expr *E, CheckerContext &C)
  - Use getMemRegionFromExpr(E, C) first.
  - If null, try to find a DeclRefExpr or MemberExpr inside E:
    - Use findSpecificTypeInChildren<DeclRefExpr>(E) or findSpecificTypeInChildren<MemberExpr>(E) and call getMemRegionFromExpr on that child expression.
  - Return the first non-null region.

- bool lenComesFromDeviceSize(const Expr *LenE, CheckerContext &C)
  - True if:
    - LenE is a CallExpr that satisfies isVirtioCreadOfRssKeySize, or
    - resolveExprRegion(LenE, C) returns a region that is in DeviceSizeSet.

- bool getConstArraySizeOfExpr(llvm::APInt &ArraySize, const Expr *DestE)
  - Attempt getArraySizeFromExpr(DestE) directly.
  - If that fails, try to find a DeclRefExpr/MemberExpr child of DestE and call getArraySizeFromExpr on that child expression.
  - Return true only if a constant array size is recovered.

- bool lengthIsProvablyBounded(CheckerContext &C, const Expr *LenE, uint64_t Limit)
  - Get SVal of Len argument: SVal LenSVal = C.getState()->getSVal(LenE, C.getLocationContext()).
  - If SymbolRef Sym = LenSVal.getAsSymbol() exists, use inferSymbolMaxVal(Sym, C). If maxVal exists and maxVal <= Limit, return true. Otherwise false.
  - If no symbol, return false (be conservative).

3) Callbacks and logic

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const

- Goal 1: Mark LHS as “device size” when assigned from virtio_creadX reading rss_max_key_size.
  - If Loc.getAsRegion() is non-null and S contains a CallExpr RHS that is a call to virtio_cread8/16/32 with arg1 containing “rss_max_key_size” (via isVirtioCreadOfRssKeySize), then:
    - State’ = State.add(DeviceSizeSet, LHSRegion)
    - C.addTransition(State’)

- Goal 2: Propagate the tag on assignments.
  - If both LHSRegion and RHSRegion exist (RHS from Val.getAsRegion()) and RHSRegion is in DeviceSizeSet, then add LHSRegion to DeviceSizeSet.
  - This covers scalar copies like: local_len = vi->rss_key_size; or vi->rss_key_size = local_len;

Notes:
- The Stmt* S in checkBind is enough to find the CallExpr on the RHS using findSpecificTypeInChildren<CallExpr>(S).
- Always ignore implicit casts on expressions when searching.

B) checkPreCall(const CallEvent &Call, CheckerContext &C) const

- Step 1: Identify sink calls.
  - If !isKnownCopyLenSink(Call, DestIdx, LenIdx) then return.

- Step 2: Determine if the length comes from device-provided rss_max_key_size.
  - const Expr *LenE = Call.getArgExpr(LenIdx);
  - If !lenComesFromDeviceSize(LenE, C) then return.

- Step 3: Try to recover destination buffer constant capacity.
  - const Expr *DestE = Call.getArgExpr(DestIdx);
  - llvm::APInt ArrSize; if (!getConstArraySizeOfExpr(ArrSize, DestE)) return;  // If we don’t know the capacity, be silent to avoid FPs.

- Step 4: Check if the analyzer can prove Len <= capacity.
  - uint64_t Limit = ArrSize.getZExtValue();
  - If lengthIsProvablyBounded(C, LenE, Limit) return;  // Safe on this path.

- Step 5: Report bug.
  - Generate a non-fatal error node on the call expression.
  - Message: “Unbounded device-provided RSS key length used”
  - Optionally attach source ranges: the len argument’s range, and if available, the assignment site where we first tagged the device size.
  - Emit a PathSensitiveBugReport.

Rationale:
- If there is a prior bound check like “if (len > VIRTIO_NET_RSS_MAX_KEY_SIZE) goto error;” the analyzer will constrain len on the normal path, inferSymbolMaxVal(...) will return a value ≤ Limit and no warning will be emitted. This mirrors the bug fix pattern.
- If no bound check is present, the maxVal is typically the full width (e.g., 255 for an 8-bit read), which exceeds the array capacity and we report a warning.

4) Optional callback

- No need to implement checkBranchCondition explicitly. The analyzer’s built-in constraint tracking is sufficient; inferSymbolMaxVal reflects prior “if” checks.
- No need for evalAssume or extra state for “checked” flags.

5) Targeting the patch pattern precisely

- The checker is tailored to flag uses where:
  - The length originates from virtio_creadX of rss_max_key_size, and
  - The length is used as a copy length into a fixed-size array (capacity derivable), and
  - There is no dominating constraint that makes length ≤ capacity.
- This directly matches the need to add “if (rss_key_size > VIRTIO_NET_RSS_MAX_KEY_SIZE) goto error;” before using the size to set/read the key.

6) Reporting

- Keep it short and clear:
  - Title: “Unbounded device-provided RSS key length used”
  - Brief description in bug report text:
    - “rss_max_key_size is used without validating against maximum key size; potential out-of-bounds.”
- Use std::make_unique<PathSensitiveBugReport> with generateNonFatalErrorNode.

7) Notes to reduce false positives

- Only flag when:
  - The len argument is directly or indirectly derived from a virtio_creadX call of rss_max_key_size, and
  - The destination’s compile-time capacity can be recovered (constant array size), and
  - The analyzer cannot prove len ≤ capacity on the current path.
- This keeps the checker focused and aligns with the exact bug pattern in the target patch.
