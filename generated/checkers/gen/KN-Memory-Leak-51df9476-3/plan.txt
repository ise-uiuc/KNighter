1) Program state customizations

- REGISTER_MAP_WITH_PROGRAMSTATE(RetSymResKindMap, SymbolRef, unsigned)
  - Maps the return-symbol of an allocation call to a resource “kind” enum (e.g., Netdev = 1).
- REGISTER_MAP_WITH_PROGRAMSTATE(RetSymLoopMap, SymbolRef, const Stmt *)
  - Maps the same return-symbol to the enclosing creation loop (ForStmt*) where the allocation happens.
- REGISTER_MAP_WITH_PROGRAMSTATE(ResKindMap, const MemRegion *, unsigned)
  - Tracks variables (their regions) that currently hold a resource of a given kind and require freeing if the iteration aborts.
- REGISTER_MAP_WITH_PROGRAMSTATE(ResLoopMap, const MemRegion *, const Stmt *)
  - Associates the tracked variable with the enclosing creation loop (ForStmt*) where the resource was created.
- REGISTER_MAP_WITH_PROGRAMSTATE(LabelCleanupMap, const LabelDecl *, bool)
  - Flags labels that lead to a cleanup loop using the pre-decrement pattern (while (--idx >= 0) …), meaning the current iteration is skipped by the cleanup.

Note: Keep the resource “kind” enum small/specific. For this checker, support at least:
- KindNetdev = 1 for alloc_etherdev()/free_netdev().

2) Callback functions and detailed implementation

A) checkBeginFunction(CheckerContext &C)

Goal: Pre-scan the function body and record labels that jump to a cleanup block which uses a pre-decrement loop, i.e. while (--idx >= 0) { ... }.

- Retrieve the current FunctionDecl and its body.
- Walk the body’s AST to find all LabelStmt nodes. For each LabelStmt L:
  - Inspect L->getSubStmt(). Search (using a small recursive walk) for a WhileStmt whose condition matches the pre-decrement cleanup pattern:
    - Condition is a BinaryOperator with opcode >=.
    - LHS (after ignoring implicit casts) is a UnaryOperator with opcode UO_PreDec.
    - UO_PreDec’s subexpression is a DeclRefExpr to some VarDecl (the loop index).
    - RHS (after ignoring implicit casts) is an IntegerLiteral equal to 0. You can use EvaluateExprToInt to verify RHS is zero.
  - If such a WhileStmt is found, insert into LabelCleanupMap: State = State->set(LabelCleanupMap, { L->getDecl(), true }).
- Update the program state with this map so that later callbacks can quickly query if a goto target label is a “pre-decrement” cleanup label.

B) checkPostCall(const CallEvent &Call, CheckerContext &C)

Goal: Detect successful resource allocations and stage the return symbol for the next bind.

- Identify known allocators:
  - alloc_etherdev (and optionally alloc_etherdev_mqs).
  - Helper: isAllocNetdev(const CallEvent&).
- If this is a known allocator:
  - Obtain the return SVal: SVal Ret = Call.getReturnValue();
  - If Ret has a SymbolRef Sym, record:
    - RetSymResKindMap[Sym] = KindNetdev.
    - RetSymLoopMap[Sym] = findSpecificTypeInParents<ForStmt>(Call.getOriginExpr(), C). Store the ForStmt* (can be nullptr if not in a loop; we’ll only warn when both allocation and goto live in the same loop).
- No report here; just stage information for checkBind.

C) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)

Goal: When an allocation return value is assigned to a variable, move tracking from return-symbol to that variable’s region.

- If Val has a SymbolRef Sym that exists in RetSymResKindMap:
  - Extract the destination region from Loc: const MemRegion* MR = Loc.getAsRegion();
  - If MR is a VarRegion or any non-null region, set:
    - ResKindMap[MR] = RetSymResKindMap[Sym].
    - ResLoopMap[MR] = RetSymLoopMap[Sym] (ForStmt pointer may be nullptr).
  - Erase Sym from RetSymResKindMap and RetSymLoopMap to avoid stale entries.

D) checkPreCall(const CallEvent &Call, CheckerContext &C)

Goal: Observe frees and clear tracked resources bound to variables.

- Identify known frees by function name:
  - free_netdev for KindNetdev. Helper: isFreeNetdev(const CallEvent&).
- For a recognized free:
  - Obtain the pointer argument’s MemRegion using getMemRegionFromExpr(Call.getArgExpr(0), C).
  - If that MemRegion MR exists in ResKindMap:
    - Erase MR from both ResKindMap and ResLoopMap.

E) checkPreStmt(const GotoStmt *GS, CheckerContext &C)

Goal: When we are about to take a goto, if the target label is a pre-decrement cleanup label and we still hold an unfreed resource created in the same loop, report a leak.

- Get the target LabelDecl*: const LabelDecl *LD = GS->getLabel();
- Query LabelCleanupMap[LD]. If absent or false, return (not our pattern).
- Determine the current enclosing ForStmt* for this goto: const ForStmt *CurLoop = findSpecificTypeInParents<ForStmt>(GS, C).
- Iterate over ResKindMap entries (MR -> Kind):
  - Retrieve the recorded loop ForStmt* LoopOfRes from ResLoopMap[MR].
  - If LoopOfRes is non-null and LoopOfRes == CurLoop:
    - This indicates a resource allocated in this creation loop remains unfreed in the current iteration, and we are jumping to a pre-decrement cleanup that will skip the current index.
    - Emit a bug report. Keep the message short:
      - “Resource allocated in this iteration is not freed before goto to cleanup; current item will be leaked.”
    - Use generateNonFatalErrorNode to create an error node and std::make_unique<PathSensitiveBugReport> to report.
    - Optionally, break after first report to avoid duplicates per Goto.

Notes:
- We do not need to inspect the IfStmt explicitly; catching the GotoStmt suffices and keeps us path-sensitive (we only warn along the path actually taking the goto).
- No need to verify frees after the goto; control leaves to the cleanup that is known to skip current item.

F) checkEndFunction(const ReturnStmt *RS, CheckerContext &C)

- Clear RetSymResKindMap, RetSymLoopMap, ResKindMap, ResLoopMap, LabelCleanupMap for cleanliness, though they should be path-local.

3) Helper functions (internal to the checker)

- bool isAllocNetdev(const CallEvent &Call):
  - Match callee identifier to “alloc_etherdev” (and optionally “alloc_etherdev_mqs”).
- bool isFreeNetdev(const CallEvent &Call):
  - Match callee identifier to “free_netdev”.
- Optional: A small utility to scan LabelStmt’s sub-tree for WhileStmt with the specific pre-decrement pattern, using:
  - dyn_cast<WhileStmt> on descendants;
  - In its condition, check BinaryOperator >=, LHS is UnaryOperator UO_PreDec on a DeclRefExpr, RHS equals 0 with EvaluateExprToInt.

4) Reporting

- Category: Resource leak on error path in creation loop.
- Message: “Leak: current iteration resource not freed before goto to cleanup that skips current item.”
- Location: At the GotoStmt.
- Describe relevant variable if possible:
  - If you can recover the variable name from MR (VarRegion->getDecl()->getName()), append: “(e.g., ‘ndev’)”.

5) Simplifications and scope

- This checker focuses on the netdev case (alloc_etherdev/free_netdev) because it matches the target patch. You can extend the alloc/free tables later.
- The cleanup pattern detection is constrained to WhileStmt with “--idx >= 0”. This mirrors the target code; you can later extend to for-loops sporting the same pre-decrement idiom.
- No alias graph is needed; we only track direct variable regions that receive the allocator’s return value. If the pointer is propagated to fields (e.g., rep->netdev) before the error, the immediate free that is expected is on the original local (ndev), which our checker covers.

6) Summary of control flow

- Allocation call → record return symbol (+ enclosing ForStmt).
- Bind return to local var (e.g., ndev) → track var region as “needs free” (+ loop).
- If an early error path performs free_netdev(ndev) → we remove tracking.
- If the error path executes a goto to a label whose cleanup loop is while (--idx >= 0) → we warn if any tracked resource was allocated in the same loop and is still not freed.
