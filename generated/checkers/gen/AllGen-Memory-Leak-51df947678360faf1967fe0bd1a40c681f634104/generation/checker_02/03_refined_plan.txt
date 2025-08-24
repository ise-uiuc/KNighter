1) Program state customization

- REGISTER_MAP_WITH_PROGRAMSTATE(LoopCurResMap, const Stmt*, const MemRegion*)
  - Key: the enclosing loop statement (ForStmt or WhileStmt).
  - Value: the MemRegion of the resource allocated for the current iteration that is not yet freed.

- REGISTER_SET_WITH_PROGRAMSTATE(CompletedResSet, const MemRegion*)
  - Resources that have been “completed” (e.g., successfully registered) so they are expected to be handled by the common cleanup, thus we don’t warn on gotos after completion.

No alias map is needed; we only match the exact variable/region used for allocation and for free/register.

2) Callback functions and how to implement them

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
- Goal: Detect “allocation assigned to a local variable inside a loop” and start tracking it as the “current-iteration resource.”
- Steps:
  1) Ensure S is a DeclStmt (initialization) or a BinaryOperator (assignment). If not, return.
  2) Using findSpecificTypeInChildren<const CallExpr>(S), get the callexpr on the RHS.
     - If there is no CallExpr, return.
     - Resolve its callee name. If it is not a netdev allocator, return.
       - Consider: alloc_etherdev, alloc_netdev, alloc_netdev_mqs (extendable list).
  3) Find the nearest enclosing loop with:
     - const ForStmt *FS = findSpecificTypeInParents<ForStmt>(S, C);
     - if (!FS) try WhileStmt similarly; select whichever is non-null as Loop.
     - If no enclosing loop, return (this checker targets per-iteration allocations).
  4) Get the destination MemRegion from Loc: const MemRegion* R = Loc.getAsRegion(); if null, return.
  5) Update state:
     - State = State->set<LoopCurResMap>(Loop, R)
     - State = State->remove<CompletedResSet>(R)
     - C.addTransition(State)

B) checkPreCall(const CallEvent &Call, CheckerContext &C) const
- Goal: Observe frees and “completion” so we don’t warn falsely.
- Steps:
  1) Identify free-like and register-like functions by name:
     - free-like: free_netdev
     - complete-like: register_netdev
  2) For free_netdev(ptr):
     - Get arg MemRegion: const Expr *ArgE = Call.getArgExpr(0); const MemRegion *ArgR = getMemRegionFromExpr(ArgE, C);
     - Determine current enclosing loop (if any) using Call.getOriginExpr() (or Call.getSourceRange begin) to find a Stmt and then findSpecificTypeInParents<ForStmt/WhileStmt>.
     - If LoopCurResMap has an entry for this Loop and its value equals ArgR:
       - Remove the mapping: State = State->remove<LoopCurResMap>(Loop)
       - Also: State = State->remove<CompletedResSet>(ArgR)
       - C.addTransition(State)
  3) For register_netdev(ptr):
     - Get arg region ArgR as above.
     - If ArgR is tracked as current for the nearest loop, consider it “completed” and stop tracking:
       - State = State->add<CompletedResSet>(ArgR)
       - State = State->remove<LoopCurResMap>(Loop)
       - C.addTransition(State)

C) check::PreStmt<const GotoStmt>(const GotoStmt *GS, CheckerContext &C) const
- Goal: When jumping to a shared exit/err/out label from within a loop, warn if the current iteration’s resource is still outstanding (not freed and not completed).
- Steps:
  1) Identify the nearest enclosing loop from GS:
     - Loop = findSpecificTypeInParents<ForStmt>(GS, C) or WhileStmt if ForStmt is null. If none, return.
  2) Lookup the current iteration resource:
     - const MemRegion *R = State->get<LoopCurResMap>(Loop); if null, return.
     - If R is in CompletedResSet, return (we only warn pre-completion).
  3) Check if target label looks like a shared cleanup label:
     - StringRef LName = GS->getLabel()->getName();
     - If LName doesn’t match common cleanup names (case-insensitive contains: "exit", "err", "out", "fail"), return; otherwise continue.
     - This heuristic reduces false positives and aligns with the kernel’s common style.
  4) Report:
     - Generate a non-fatal error node: if (!N) N = C.generateNonFatalErrorNode();
     - Emit a PathSensitiveBugReport with a short message:
       - “Leaked current-iteration resource: free before goto to cleanup.”
     - Optionally include a note at the allocation site if it is available in the ExplodedGraph (the store site tracked by checkBind).

D) checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const (optional)
- Clear maps/sets implicitly when function finishes; no explicit work needed because maps are tied to ProgramState and path ends here. You can leave this callback unimplemented.

3) Helper predicates/utilities

- isNetdevAlloc(const CallExpr* CE) or callee name string:
  - Returns true for {"alloc_etherdev", "alloc_netdev", "alloc_netdev_mqs"}.

- isFreeNetdev(const CallEvent &Call):
  - Callee name equals "free_netdev".

- isRegisterNetdev(const CallEvent &Call):
  - Callee name equals "register_netdev".

- getEnclosingLoop(const Stmt *S, CheckerContext &C):
  - Try findSpecificTypeInParents<ForStmt>(S, C); if null, try WhileStmt; return whichever found.

- isExitLikeLabel(const GotoStmt *GS):
  - Name contains one of {"exit", "err", "out", "fail"} (case-insensitive). You can use GS->getLabel()->getName().

4) Rationale and how this catches the target pattern

- In the buggy pattern, the per-iteration resource (ndev) is allocated inside the loop and tracked by LoopCurResMap.
- When rvu_rep_devlink_port_register(rep) fails, code does “goto exit” before register_netdev is called and before any free_netdev(ndev). Our state still holds the current resource (not in CompletedResSet and not freed).
- PreStmt(GotoStmt) fires, recognizes an “exit”-like label and an outstanding current-iteration resource, and reports the leak risk: the shared cleanup typically frees only previous iterations (e.g., while (--i >= 0)), skipping the current one. The fix is to free the just-allocated resource before the goto, matching the provided patch.
- If code frees the resource before goto (free_netdev), checkPreCall removes it from the map, so no warning is reported.
- If code has already “completed” the resource (register_netdev), we suppress warnings for later gotos, avoiding false positives past the setup point.

5) Notes to keep it simple and robust

- Keep the alloc/free/register name lists small and focused; the checker is targeted to the netdev pattern from the patch.
- We do not attempt to precisely model the exit label body; instead we rely on the label name heuristic and the presence of an outstanding unfreed resource in the current loop iteration.
- No alias tracking is needed because free_netdev is typically called on the same variable that received the alloc. If you later need aliasing, integrate a simple PtrAliasMap via checkBind, but start without it for simplicity.
