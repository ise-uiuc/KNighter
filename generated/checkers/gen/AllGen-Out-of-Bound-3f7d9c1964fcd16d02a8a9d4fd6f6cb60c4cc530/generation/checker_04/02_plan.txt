1) Program state customizations
- REGISTER_SET_WITH_PROGRAMSTATE(DeviceLenRegions, const MemRegion*)
  - Regions that hold device-provided length values (e.g., vi->rss_key_size) that currently have no proven upper-bound check.
- REGISTER_SET_WITH_PROGRAMSTATE(DeviceLenSyms, SymbolRef)
  - Symbols produced by device-config read calls that are used as “length” before being stored to a region.
- REGISTER_SET_WITH_PROGRAMSTATE(ValidatedRegions, const MemRegion*)
  - Regions proven to have been validated against the required max bound.
- REGISTER_SET_WITH_PROGRAMSTATE(ValidatedSyms, SymbolRef)
  - Symbols proven to have been validated against the required max bound.

2) Helper configuration/constants
- Known device-config read functions (exact-name match):
  - virtio_cread8, virtio_cread16, virtio_cread32
- Known (ptr,len) style calls to flag if len is device-provided and unvalidated:
  - memcpy (len index = 2), memmove (len index = 2), sg_init_one (len index = 2)
- The specific macro name we want to see in a validation check:
  - "VIRTIO_NET_RSS_MAX_KEY_SIZE"
- Use provided utilities:
  - findSpecificTypeInParents/findSpecificTypeInChildren
  - getMemRegionFromExpr
  - ExprHasName

3) Callbacks and detailed steps

A) checkBeginFunction
- Clear all four sets (DeviceLenRegions, DeviceLenSyms, ValidatedRegions, ValidatedSyms) for a fresh, per-function analysis state.

B) checkPostCall — identify device-provided length on assignment/initialization
- If callee name is one of virtio_cread8/16/32:
  - Record the call's return SymbolRef (if any) into DeviceLenSyms.
  - Also attempt to map the call result to a destination region:
    - Find a parent BinaryOperator of kind “=” containing this call (RHS). If found:
      - Extract LHS, get its MemRegion via getMemRegionFromExpr; if present:
        - Add region to DeviceLenRegions; remove it from ValidatedRegions if present.
    - Else, find a parent DeclStmt (initialization like "u8 len = virtio_cread8(...)"):
      - For each initialized VarDecl whose init contains the call, get its MemRegion; add it to DeviceLenRegions; remove it from ValidatedRegions if present.

C) checkBind — propagate device-length and validation across assignments
- When binding a value to a location:
  - Let DestR be the MemRegion of LHS; get MemRegion from LHS expression (if any).
  - If RHS is:
    - A MemRegion that is in DeviceLenRegions OR
    - A SymbolRef that is in DeviceLenSyms
    then add DestR to DeviceLenRegions.
  - If RHS is:
    - A MemRegion in ValidatedRegions OR
    - A SymbolRef in ValidatedSyms
    then also add DestR to ValidatedRegions (propagate validated-ness).
  - Do not remove validated if RHS is not validated; only add.

D) checkBranchCondition — detect the required validation pattern
- Goal: mark the device-provided len as validated if compared against VIRTIO_NET_RSS_MAX_KEY_SIZE.
- Inspect the condition expression:
  - Try dyn_cast to BinaryOperator; if not, use findSpecificTypeInChildren<BinaryOperator>(Condition).
  - If a BinaryOperator with comparison opcode (>, >=, <, <=, ==, !=) is found:
    - For each side L and R:
      - Extract MemRegion of subexpr (getMemRegionFromExpr). Also try extracting SymbolRef by querying SVal from the subexpr.
      - The other side (counterpart) is checked for macro text: use ExprHasName(otherSideExpr, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C).
      - If either a region in DeviceLenRegions or a symbol in DeviceLenSyms is found on one side, and the other side textually contains "VIRTIO_NET_RSS_MAX_KEY_SIZE":
        - Mark that region/symbol as validated: add to ValidatedRegions/ValidatedSyms.
- Rationale: This mirrors the added patch "if (vi->rss_key_size > VIRTIO_NET_RSS_MAX_KEY_SIZE) { ... }".

E) checkPreCall — flag unvalidated use of device-provided length as size
- If call is one of the known (ptr,len) style functions:
  - Identify “length” argument index (2 for memcpy/memmove/sg_init_one).
  - Let LenE be the length arg Expr; obtain:
    - MemRegion RLen via getMemRegionFromExpr(LenE).
    - SymbolRef SLen from C.getSVal(LenE, ...).getAsSymbol().
  - Consider the length “tainted by device” if RLen ∈ DeviceLenRegions OR SLen ∈ DeviceLenSyms.
  - Consider the length “validated” if RLen ∈ ValidatedRegions OR SLen ∈ ValidatedSyms.
  - If device-tainted and not validated:
    - Emit a bug.
    - Message: "Unvalidated device-provided length used as copy size (possible OOB)."
- Note: We intentionally do not require confirming the destination fixed-size buffer at this step; the pattern’s essence is using untrusted device length directly as a size in a dereferencing call. This keeps the rule simple and aligned with the patch motivation.

4) Reporting
- Use generateNonFatalErrorNode; if node is null, return.
- Use std::make_unique<PathSensitiveBugReport> with a concise message:
  - Title: "Unvalidated device-provided length"
  - Description: "Unvalidated device-provided length used as copy size (possible OOB)."
- Optionally add a note at the source of the device-length assignment (if tracked via parent BinaryOperator/DeclStmt) to help navigation.

5) False-positive controls and refinements
- Only treat lengths coming from the exact virtio_cread8/16/32 functions to minimize noise.
- Only set “validated” if the comparison condition textually mentions "VIRTIO_NET_RSS_MAX_KEY_SIZE".
- Do not attempt generic MAX detection or value inference to keep the rule precise for the target pattern.

6) Optional minor enhancements (if desired later)
- Also recognize additional data movement APIs frequently used with (ptr,len), like memcpy_toio/memcpy_fromio, skb_put_data, or other scatterlist initializers (keep indices similarly defined).
- Use inferSymbolMaxVal(Sym, C) to suppress warnings if the solver has already constrained the symbol to be ≤ a known bound (if obtainable). This is optional and not necessary for the core pattern detection.
- For validations, also recognize “if (len > MAX) return -EINVAL;” patterns by treating any branch comparison (regardless of taken direction) as a validation event for the symbol/region on both successors. This keeps path-sensitivity low while being practical.

7) Summary of minimal flow to catch the given patch
- PostCall of virtio_cread8 → mark LHS (vi->rss_key_size) as DeviceLenRegion.
- If BranchCondition compares vi->rss_key_size against VIRTIO_NET_RSS_MAX_KEY_SIZE → mark as validated.
- PreCall of sg_init_one (or memcpy) where length arg is vi->rss_key_size:
  - If not validated → report.
