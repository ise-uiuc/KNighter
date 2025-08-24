1) Program state

- REGISTER_SET_WITH_PROGRAMSTATE(DevmAllocSyms, SymbolRef)
  - Purpose: remember which pointer symbols originate from devm-managed allocators (devm_kcalloc/devm_kmalloc/…).
  - We deliberately track SymbolRef, not variable regions. In CSA, the same returned pointer symbol flows through assignments and arguments, so alias tracking is usually unnecessary for this use case.

- No other traits/maps needed. We will not maintain an alias map to keep the checker simple. We rely on the symbolic value propagation of CSA.

2) Callbacks and how to implement them

A) checkPostCall — mark devm-managed allocations

- Goal: whenever a devm-managed allocator returns a pointer, record the returned SymbolRef in DevmAllocSyms.
- Detect allocators:
  - Implement helper isDevmAllocator(const CallEvent &Call):
    - Return true if callee name is one of:
      - devm_kcalloc
      - devm_kmalloc
      - devm_kmalloc_array
      - devm_kzalloc
      - devm_kcalloc_node / devm_kmalloc_node (optional, if you want broader coverage)
    - Keep the list tight to avoid FPs.
- Implementation steps:
  1. If !isDevmAllocator(Call), return.
  2. SVal Ret = Call.getReturnValue(); extract SymbolRef:
     - SymbolRef Sym = Ret.getAsSymbol();
     - If null, also try if Ret.getAsRegion() is a SymbolicRegion and get its symbol (SymbolicRegion->getSymbol()).
  3. If a SymbolRef was obtained, insert it into DevmAllocSyms via State = State->add<DevmAllocSyms>(Sym) and C.addTransition(State).

B) checkPreCall — detect manual frees of devm-managed pointers

- Goal: flag calls that free a pointer which originates from a devm_* allocator.
- Recognize manual-free-like functions and which argument is freed:
  - Implement helper functionKnownToFree(const CallEvent &Call, SmallVectorImpl<unsigned> &FreedParams):
    - If callee name equals:
      - "kfree" -> FreedParams = {0}
      - "kvfree" -> {0}
      - "vfree" -> {0}
      - "pinctrl_utils_free_map" -> {1}  // The second argument is freed
    - Return true if matched, false otherwise.
- Implementation steps:
  1. If !functionKnownToFree(Call, FreedParams), return.
  2. For each index I in FreedParams:
     - const Expr *ArgE = Call.getArgExpr(I); SVal ArgV = Call.getArgSVal(I).
     - Skip if definitely null:
       - If ArgV.isZeroConstant() (or using state assumptions it simplifies to only null), continue to next parameter.
     - Extract the pointer symbol:
       - SymbolRef Sym = ArgV.getAsSymbol();
       - If null, try:
         - If ArgV.getAsRegion() is a SymbolicRegion, get its symbol.
         - If ArgV.getAsRegion() is an Element/Field region whose base is SymbolicRegion, get the base’s symbol.
     - If Sym is non-null and State->contains<DevmAllocSyms>(Sym):
       - This is a manual free of a devm-managed pointer. Report a bug.
       - Create ExplodedNode *N = C.generateNonFatalErrorNode();
       - If N is non-null, create a PathSensitiveBugReport:
         - Name: "double free of devm-managed pointer"
         - Short message: "Manual free of devm_* allocated pointer (double free)"
         - Add the argument source range ArgE->getSourceRange() as the primary range.
         - Optionally add a note: the bug path will usually show the allocation; no extra state needed.
       - Emit the report and return.
- Rationale: The devm-managed allocation will be freed automatically on device detach. Manual free via kfree/kvfree or helpers (like pinctrl_utils_free_map) introduces a double free risk. We specifically handle pinctrl_utils_free_map freeing its 2nd parameter.

C) Optional: checkEndFunction / others

- Not necessary. We only need checkPostCall and checkPreCall for this pattern.
- No checkBind: symbol propagation naturally keeps the same pointer symbol across assignments in CSA, so alias-tracking maps are not needed for this simple pattern.

3) Additional details and safeguards

- Avoid false positives on NULL pointers: before reporting, ensure the argument is not definitely NULL (skip reports if analyzer proves it’s NULL).
- Keep the known free table small and focused. The primary target is:
  - kfree/kvfree/vfree
  - pinctrl_utils_free_map (index 1)
- Keep the known devm allocators focused. The primary target for this patch is devm_kcalloc, but include its immediate siblings to make the checker generally useful.
- Reporting:
  - Keep message short: "Manual free of devm_* allocated pointer (double free)"
  - One report per call site. No need to record “already reported” state.

4) Summary of flow

- devm_* allocator returns pointer -> checkPostCall taints its SymbolRef by inserting into DevmAllocSyms.
- Later, a manual free function is called -> checkPreCall checks the freed argument’s symbol against DevmAllocSyms; if present and pointer not proven NULL, report.

This minimal design reliably finds the target bug pattern exemplified by:
- map = devm_kcalloc(...);
- ...
- pinctrl_utils_free_map(..., map, ...); // frees parameter 1 internally via kfree(map)
and similar cases where a devm-managed pointer is manually freed.
