1) Program state customization

- REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion*, unsigned)
  - Tracks pointer variables that point to per-CPU storage and how they were obtained.
  - Value is a bitmask:
    - bit 0 (1): isTracked (always set for entries)
    - bit 1 (2): isRemote (true if obtained via per_cpu_ptr(..., cpu) where cpu != smp_processor_id(); false if via this_cpu_ptr(...) or per_cpu_ptr(..., smp_processor_id()))
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks simple aliases between pointer variables so access classification can be propagated (p2 = p1).

Rationale:
- We only need to know whether a pointer variable is a per-CPU pointer and whether it represents a “remote” per-cpu access or a “local (this CPU)” per-cpu access. This is enough to detect missing READ_ONCE/WRITE_ONCE on remote access and RMW patterns on local access.


2) Callbacks and how to implement them

A. checkPostStmt(const DeclStmt *DS, CheckerContext &C) const
- Goal: Track initializations of pointer variables from per_cpu_ptr/this_cpu_ptr.
- Steps:
  - Iterate each VarDecl with an initializer in DS.
  - If the initializer is or contains a CallExpr:
    - Extract callee name string via getDirectCallee()->getNameAsString() (if available), otherwise use ExprHasName on the initializer expression with "per_cpu_ptr" or "this_cpu_ptr".
    - If it is per_cpu_ptr or this_cpu_ptr:
      - Determine “remote vs local”:
        - For this_cpu_ptr => local (isRemote = false).
        - For per_cpu_ptr(..., cpuExpr):
          - If cpuExpr contains "smp_processor_id" by ExprHasName(cpuExpr, "smp_processor_id"), mark local; else mark remote (isRemote = true).
      - Obtain the MemRegion of the declared variable using getMemRegionFromExpr on a DeclRefExpr to the VarDecl (you can get it by creating a DeclRefExpr from the VarDecl or, simpler, by using State->getLValue(VarDecl, LCtx).getAsRegion()).
      - Insert into PerCpuPtrMap: (VarRegion -> flags: isTracked | isRemote?2:0).
  - This step ensures we start tracking pointer variables bound to per-CPU storage and whether the access is “remote” or “local” by construction.

B. checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
- Goal: Track assignments to pointer variables either from per_cpu_ptr/this_cpu_ptr or from another tracked pointer (alias propagation).
- Steps:
  - Identify LHS region: if Loc is a MemRegionVal for a pointer-typed Var/Field, get MemRegion* LHSReg.
  - If S is a BinaryOperator with isAssignmentOp():
    - Extract RHS expression R:
      - If R contains a CallExpr to per_cpu_ptr/this_cpu_ptr (use findSpecificTypeInChildren<CallExpr>(R) and name matching as in A):
        - Determine “remote vs local” same way as in A.
        - Map LHSReg -> flags in PerCpuPtrMap (overwrite previous).
      - Else if RHS is a pointer variable already in PerCpuPtrMap:
        - Use getMemRegionFromExpr on RHS to get RHSReg.
        - If RHSReg is in PerCpuPtrMap, copy flags from RHSReg to LHSReg and also set PtrAliasMap[LHSReg] = RHSReg.
      - Else:
        - If LHSReg was tracked and RHS is not per-cpu/alias, you may remove LHSReg from PerCpuPtrMap (optional hygiene). Not strictly required for this checker to work.

C. checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const
- Goal: Detect read-modify-write on per-CPU fields without READ_ONCE/WRITE_ONCE.
- Steps:
  - Let LHS = CAO->getLHS()->IgnoreParenImpCasts().
  - If LHS is (or contains) a MemberExpr (e.g., statc->field or statc->arr[i]):
    - Extract the base expression B = MemberExpr->getBase()->IgnoreParenImpCasts().
    - If B is a DeclRefExpr to a pointer variable:
      - Get its MemRegion via getMemRegionFromExpr(B, C).
      - If in PerCpuPtrMap as isTracked:
        - If it is a per-CPU pointer (local or remote — for remote we’ll also catch in checkLocation), warn specifically for RMW on per-CPU field:
          - Message: "Per-CPU field updated with compound assignment without READ_ONCE/WRITE_ONCE."
        - Rationale: Kernel fix replaced x += delta with explicit READ_ONCE/WRITE_ONCE sequence; compound ops are inherently RMW and should be avoided here.

D. checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const
- Goal: Detect ++/-- on per-CPU fields without READ_ONCE/WRITE_ONCE.
- Steps:
  - If UO is increment/decrement and its subexpr is a MemberExpr on a tracked per-CPU pointer (as identified in C), report:
    - "Per-CPU field increment/decrement without READ_ONCE/WRITE_ONCE."

E. checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const
- Goal: Enforce READ_ONCE on remote reads and WRITE_ONCE on remote writes; also catch simple writes on per-CPU fields missing WRITE_ONCE.
- Steps:
  - If S is not an Expr, return.
  - Using findSpecificTypeInChildren<MemberExpr>(cast<Expr>(S)):
    - If found, extract MemberExpr (ME).
    - Obtain the base expression B = ME->getBase()->IgnoreParenImpCasts().
    - If B is a DeclRefExpr to a pointer variable:
      - Get MemRegion BReg via getMemRegionFromExpr(B, C).
      - If BReg is tracked in PerCpuPtrMap:
        - Determine whether this is a remote pointer (isRemote flag).
        - Check macro wrapping:
          - Use ExprHasName(cast<Expr>(S), "READ_ONCE") for reads and ExprHasName(cast<Expr>(S), "WRITE_ONCE") for writes. Additionally, check parents for fallback: climb via findSpecificTypeInParents<Expr>(S, C) if needed and apply ExprHasName to the nearest parent Expression (best-effort).
        - If IsLoad and isRemote and not wrapped by READ_ONCE, report:
          - "Remote per-CPU read without READ_ONCE."
        - If !IsLoad (store) and isRemote and not wrapped by WRITE_ONCE, report:
          - "Remote per-CPU write without WRITE_ONCE."
        - Optional conservative rule (helps catch the 'x = 0' local clear in hot path):
          - If !IsLoad and not wrapped by WRITE_ONCE (regardless of isRemote), report:
            - "Per-CPU field write without WRITE_ONCE; may race with cross-CPU access."
          - This is a heuristic to surface risky plain writes to per-CPU counters. If you want to be stricter, only enable this when isRemote == true.

F. checkBind (alias propagation)
- Already specified in B. Also, when p2 = p1 and p1 is in PtrAliasMap, transitively map to the ultimate source so that future lookups for p2 resolve to the same flags.
- If a tracked pointer is assigned NULL or some non-percpu expression, optionally remove from PerCpuPtrMap.

G. Reporting
- On each violation above, create a non-fatal error node and emit a short bug report:
  - Use std::make_unique<PathSensitiveBugReport>.
  - Example messages:
    - "Remote per-CPU read without READ_ONCE."
    - "Remote per-CPU write without WRITE_ONCE."
    - "Per-CPU field updated with compound assignment without READ_ONCE/WRITE_ONCE."
    - "Per-CPU field increment/decrement without READ_ONCE/WRITE_ONCE."
    - "Per-CPU field write without WRITE_ONCE; may race with cross-CPU access."

3) Helper details and heuristics

- Identifying per_cpu_ptr/this_cpu_ptr:
  - Prefer matching via callee identifier name when CallExpr->getDirectCallee() exists.
  - Otherwise, rely on ExprHasName(InitOrRHSExpr, "per_cpu_ptr") or ExprHasName(..., "this_cpu_ptr").
- Determining "remote":
  - For per_cpu_ptr(base, cpuExpr): examine cpuExpr via ExprHasName(cpuExpr, "smp_processor_id"). If it contains "smp_processor_id", classify as local; otherwise remote.
  - For this_cpu_ptr(...): classify as local.
- Finding MemberExpr inside S in checkLocation:
  - Use findSpecificTypeInChildren<MemberExpr>(cast<Expr>(S)) to get the member access causing the load/store. This works for both direct field and array element cases (e.g., statc->arr[i]).
- Macro checks:
  - Using ExprHasName on the source of the expression S to detect "READ_ONCE" or "WRITE_ONCE". This is robust for Linux macro usage and avoids needing to inspect volatile qualifiers in the AST.
- Aliases:
  - For p2 = p1 where both are pointers, if p1 is tracked, map p2 with same flags. Maintain PtrAliasMap to chain aliases. On lookup, resolve transitively to the ultimate source if needed (best-effort).

4) Minimal set of callbacks to implement

- checkPostStmt(const DeclStmt *DS, CheckerContext &C) const
- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
- checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const
- checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const
- checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const

This set keeps the checker simple and focused:
- Build a map of per-CPU pointers and whether they imply remote access.
- Flag unsafe remote reads/writes not wrapped with READ_ONCE/WRITE_ONCE.
- Flag RMW patterns on per-CPU fields lacking READ_ONCE/WRITE_ONCE.
- Optionally flag plain writes to per-CPU fields not using WRITE_ONCE.
