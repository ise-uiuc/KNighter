Plan

1. Program state customization
- REGISTER_SET_WITH_PROGRAMSTATE(AllocSymSet, SymbolRef)
  - Records symbols returned by heap allocators in this function (e.g., kmalloc/kzalloc/kcalloc/etc.).
- REGISTER_SET_WITH_PROGRAMSTATE(OwnedRegionSet, const MemRegion *)
  - Records memory regions that this function has explicitly taken ownership of by assigning an allocator return into them.

2. Auxiliary per-function metadata (not in program state)
- Maintain a per-function map LabelIncomingCount: DenseMap<const LabelStmt*, unsigned>
  - Tracks how many GotoStmt jump to each LabelStmt in the current function. We consider labels with count >= 2 as shared error/cleanup labels.
- Build and clear this map in per-function callbacks.

3. Callback selection and implementation details

3.1 checkBeginFunction
- Purpose: Pre-scan the function body to compute LabelIncomingCount.
- Steps:
  - Retrieve the current function body Stmt from Ctx.getLocationContext()->getDecl().
  - Traverse the body AST:
    - Collect all LabelStmt nodes into a map LabelDecl* -> LabelStmt* (via LabelStmt->getDecl()).
    - For each GotoStmt, obtain its LabelDecl with GotoStmt->getLabel(), resolve to LabelStmt through the previous map, and increment LabelIncomingCount[LabelStmt].
  - Store LabelIncomingCount in a checker member map keyed by the current FunctionDecl pointer (or current LocationContext root). Clear or overwrite on every function entry.

3.2 checkPostCall
- Purpose: Track allocator return symbols (to later detect local ownership when assigned) and avoid over-approximating unknown callees.
- Steps:
  - If callee identifier name is one of {kmalloc, kzalloc, kcalloc, krealloc, kvzalloc, kvmalloc, devm_kmalloc, devm_kzalloc, devm_kcalloc} (extendable):
    - Obtain the return SVal: Call.getReturnValue().
    - If it has a SymbolRef (retSym), add it to AllocSymSet.
  - No reporting here.

3.3 checkBind
- Purpose: Record when this function explicitly takes ownership of a region by assigning an allocator’s return value into it.
- Steps:
  - Extract the destination region from Loc (Loc.getAsRegion()).
  - If no region, return.
  - If Val has a SymbolRef and that symbol is in AllocSymSet:
    - Insert the destination region into OwnedRegionSet.
  - Notes:
    - This will mark “owned” when we do things like p = kmalloc(...); or mt->fc = kmalloc(...); which is exactly the ownership we want to accept as safe to kfree in cleanup.
    - We do not attempt alias tracking here to keep it simple. The target bug is a field (mt->fc) not assigned in this function at all.

3.4 checkPreCall
- Purpose: Detect freeing in a shared cleanup label of a region that isn’t owned by this function.
- Steps:
  - Identify frees: if Call callee name in {kfree, kvfree, vfree}.
  - Get the first argument expression E = Call.getArgExpr(0).
  - Restrict to freeing a struct field only:
    - If E->IgnoreParenImpCasts() is not a MemberExpr, return (reduces false positives and captures the mt->fc pattern).
  - Obtain the freed region via getMemRegionFromExpr(E, C). If null, return.
  - Check ownership: if the freed region is NOT in OwnedRegionSet, continue; otherwise, return (we own it, freeing is expected).
  - Determine if we are in a cleanup label:
    - Use findSpecificTypeInParents<LabelStmt>(Call.getOriginExpr() or the Call’s statement, C) to find the nearest parent LabelStmt, L.
    - If no parent LabelStmt, return (we only warn for label-based cleanups).
    - Lookup LabelIncomingCount[L]; if count < 2, return (not a shared error label; reduce FP).
  - If all conditions met, report:
    - Generate a non-fatal error node and emit a PathSensitiveBugReport with a short message like:
      - “Freeing unowned field in shared error label; possible double free.”
    - Add the free call as the primary location.

3.5 checkEndFunction
- Purpose: Clear per-function label metadata.
- Steps:
  - Erase the current function’s LabelIncomingCount entry from the checker’s member map to avoid leaking across functions.

4. Notes and heuristics
- Why this catches the target bug:
  - The problematic free is kfree(mt->fc) under a shared cleanup label with multiple gotos.
  - In the function, mt->fc is never assigned from an allocator return; hence, the region won’t be marked Owned.
  - The checker warns only when:
    - The freed expression is a struct field (mt->fc), AND
    - It is within a shared cleanup label (>= 2 gotos), AND
    - The field wasn’t marked as owned by this function.
  - This aligns with the root cause: a shared error label frees a resource not guaranteed to be allocated/owned at that point, potentially double freeing callee-managed memory.

- Optional small improvements (keep simple if not needed):
  - Expand allocator list if necessary.
  - If desired, allow OwnedRegionSet marking when the RHS is a known non-null constant buffer allocator or factory function (extend checkPostCall).
  - You may also add a check that the label name contains “free” or “err” using LabelStmt->getName() or source text, but the incoming-count heuristic is stronger and language-agnostic.

5. Utility functions used
- getMemRegionFromExpr for region extraction of the freed argument.
- findSpecificTypeInParents<LabelStmt> to determine if the free happens under a label.
- ExprHasName is not required (we use CallEvent callee name); can be used as fallback if needed.

6. Reporting
- Use std::make_unique<PathSensitiveBugReport>.
- Message: “Freeing unowned field in shared error label; possible double free.”
- Point to the kfree call location.

This plan stays simple and focused while being path-sensitive enough to catch the specific kernel pattern without requiring heavy alias reasoning or inter-procedural summaries.
