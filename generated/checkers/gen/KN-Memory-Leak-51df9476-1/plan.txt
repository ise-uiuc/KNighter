Plan to detect “leak of current loop iteration’s net_device when goto exit is taken before register_netdev”


1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(PendingNetdevMap, const MemRegion*, const Stmt*)
  - Key: the MemRegion of a net_device pointer variable that currently owns an allocated net_device in this loop iteration.
  - Value: the allocation site statement (for diagnostics). Presence in this map means “allocated and not yet registered/freed.”

- REGISTER_MAP_WITH_PROGRAMSTATE(NetdevLoopMap, const MemRegion*, const Stmt*)
  - Key: same MemRegion as above.
  - Value: the nearest enclosing loop statement (ForStmt/WhileStmt/DoStmt) where the allocation happened. Used to tie the “pending” object to its loop iteration.

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer aliases so a free_netdev done through an alias (e.g. rep->netdev) is recognized. Key is destination pointer region, value is its current source pointer region.
  - Keep this simple: only record on direct pointer-to-pointer assignments; no need to propagate through non-pointer types.

- No other traits are necessary.


2) Callback functions and how to implement

A) checkBeginFunction / checkEndFunction
- On function entry (checkBeginFunction): clear all three maps to avoid state bleed across functions.
- On function exit (checkEndFunction): no special action needed (state is discarded), but safe to clear maps if desired.

B) checkBind (track allocations bound to a pointer and record aliases)
- Goal 1: Detect “ptr = alloc_etherdev(...);” done inside a loop and mark ptr as “pending net_device” of this iteration.
  - For each bind:
    - Use findSpecificTypeInChildren<CallExpr>(S) to see if the RHS contains a CallExpr to one of:
      - alloc_etherdev, alloc_etherdev_mqs, alloc_netdev, alloc_netdev_mqs
    - Ensure the LHS is a pointer-typed region: auto Rdst = Loc.getAsRegion(); if (!Rdst) return.
    - Find the nearest loop using findSpecificTypeInParents<ForStmt/WhileStmt/DoStmt>(S, C). If none, skip to reduce noise.
    - Insert into PendingNetdevMap[Rdst] = S.
    - Insert into NetdevLoopMap[Rdst] = that loop Stmt*.
- Goal 2: Record pointer aliases to be able to match free_netdev performed via an alias.
  - If RHS is a load of another pointer (e.g., p2 = p1; or rep->netdev = ndev;), obtain both regions:
    - Rdst = Loc.getAsRegion()
    - Rsrc = getMemRegionFromExpr(RHS-Expr, C) (derive RHS Expr via AST from S or SVal if accessible)
  - If both regions exist and are pointer-typed, set PtrAliasMap[Rdst] = Rsrc (overwriting previous mapping).
  - Do not mutate PendingNetdevMap here.

C) checkPostCall (observe register/free and remove from pending)
- If callee is register_netdev:
  - Extract argument 0 expression, get its region ArgR via getMemRegionFromExpr.
  - Canonicalize aliases: follow PtrAliasMap repeatedly (bounded by a few steps) to resolve to a base region BaseR.
  - If PendingNetdevMap contains BaseR, remove BaseR from PendingNetdevMap and NetdevLoopMap (it is now “registered/owned,” so this checker no longer cares).
- If callee is free_netdev:
  - Extract argument 0 region ArgR and canonicalize via PtrAliasMap to BaseR.
  - If PendingNetdevMap contains BaseR, remove BaseR from PendingNetdevMap and NetdevLoopMap (freed).

D) check::BranchCondition (detect error path with goto exit/out/err and missing immediate free)
- For the incoming Condition expression:
  - Get the parent IfStmt via findSpecificTypeInParents<IfStmt>(Condition, C).
  - Let Then = IfStmt->getThen().
  - Search Then for a GotoStmt via findSpecificTypeInChildren<GotoStmt>(Then). If none, return.
  - If found, try to reduce false positives by checking the target label name:
    - LabelDecl *LD = GotoStmt->getLabel(); Name = LD->getName(). Warn only if Name equals “exit” or “out” or starts with “err” or “error”.
  - Find the nearest enclosing loop: LoopS = findSpecificTypeInParents<ForStmt/WhileStmt/DoStmt>(IfStmt, C). If none, return.
  - For each entry R in PendingNetdevMap:
    - If NetdevLoopMap[R] != LoopS, continue (not the current loop iteration).
    - Check whether Then contains a free_netdev() call for R or any alias of R:
      - Walk Then for CallExpr to “free_netdev”.
      - For each such call, get arg region ArgR (getMemRegionFromExpr) and canonicalize using PtrAliasMap to BaseR. If BaseR == R, then this path frees the current iteration’s net_device: do not warn for R.
    - If no free_netdev(R) exists in Then, emit a bug report at the GotoStmt location (or at the IfStmt) for this R.

Notes:
- We do not need to verify the specific “err” variable or result value; the presence of the goto to an exit-like label inside the loop, combined with a currently pending unregistered/unfreed net_device, is sufficient to model the bug.
- We intentionally consider only the “immediate free before goto” requirement. The well-known cleanup pattern “while (--idx >= 0) free previously created …” would miss the current iteration, which is precisely what we want to catch.

E) Optional: checkPostCall for error-producing functions (not required)
- Not necessary for this pattern; the BranchCondition + Goto detection is enough.

F) Reporting
- Create a BugType like “Resource leak in loop iteration (net_device)”.
- Message: “missing free_netdev for current iteration before goto exit”
- Use generateNonFatalErrorNode and emit a PathSensitiveBugReport, optionally adding a note with the alloc site stored in PendingNetdevMap[R] for better guidance.


3) Helper details

- Canonicalize aliases:
  - Implement a small loop: while (auto R2 = State->get<PtrAliasMap>(R)) R = R2; limit to e.g. 4 steps to avoid cycles.
  - When comparing argument regions vs pending region, compare canonical regions.

- Allocation function names:
  - alloc_etherdev, alloc_etherdev_mqs, alloc_netdev, alloc_netdev_mqs (extendable via a small array).

- Label name heuristic:
  - Accept names: “exit”, “out”, “error”, starting with “err” or “out”. This keeps FPs low and matches common kernel patterns.

- Clean up state:
  - When a pending region is removed due to free/register, also remove its PtrAliasMap entries where it is a key (optional but helps keep state small).


4) Why this catches the target patch
- In the buggy function, within the for loop, ndev is allocated, but on the failure branch after rvu_rep_devlink_port_register(rep), the then-branch only “goto exit;” without calling free_netdev(ndev).
- Our checker marks ndev as pending for the loop, sees an If with goto exit in the same loop and no free_netdev in the then-branch, and reports.
- After the patch, the then-branch contains free_netdev(ndev) before goto exit, so the checker sees the free and remains silent.
