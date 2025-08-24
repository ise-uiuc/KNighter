Plan

1) Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion*, unsigned)
  - Tracks which pointer variables are known to point to per-CPU storage.
  - Value meaning: 1 = obtained via this_cpu_ptr(), 2 = obtained via per_cpu_ptr(), both are “per-CPU” for our purposes. We only use the presence in the map to decide “per-CPU pointer”.

Rationale: We keep it simple and intra-procedural. We track pointer variables directly initialized with this_cpu_ptr()/per_cpu_ptr() and propagate this attribute through simple pointer-to-pointer assignments via checkBind. No additional traits or sets are needed.

2) Helper predicates/utilities (lightweight, local in the checker; use provided utility helpers where applicable)
- isPerCpuCtorName(StringRef N): returns true if N is "this_cpu_ptr" or "per_cpu_ptr".
- isPerCpuCtorCall(const CallEvent &Call): returns true if callee name matches isPerCpuCtorName.
- isPerCpuType(QualType QT): if QT is a pointer to a record type, check the pointed-to record name; return true if the record name contains "percpu" (case-insensitive) or ends with "_percpu".
- isPerCpuBaseExpr(const Expr *Base, CheckerContext &C):
  - If Base has a MemRegion and is present in PerCpuPtrMap, return true.
  - Else, check Base’s type with isPerCpuType(). If true, return true.
  - Else, false.
- sameFieldRegion(const Expr *E1, const Expr *E2, CheckerContext &C):
  - Use getMemRegionFromExpr(E1, C) and getMemRegionFromExpr(E2, C); return true if both non-null and equal.
- rhsReadsSameField(const MemberExpr *LHSME, const Expr *RHS, CheckerContext &C):
  - Use findSpecificTypeInChildren<MemberExpr>(RHS). If found and sameFieldRegion(LHSME, that MemberExpr, C), return true; else false.
- isConstInt(const Expr *E, CheckerContext &C, llvm::APSInt &Out):
  - Use EvaluateExprToInt to decide if RHS is a compile-time integer constant; if true, set Out and return true.

3) Bug types/messages
- Create a single BugType: "Non-atomic per-CPU access"
- Two short messages, depending on what we detect:
  - "Non-atomic read-modify-write on per-CPU field; use READ_ONCE()/WRITE_ONCE()."
  - "Plain write to per-CPU field; use WRITE_ONCE()."

4) Chosen callbacks and their responsibilities

4.1) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
Purpose: both track per-CPU pointers and detect the target patterns because assignments/compound-assignments/inc/dec all end up binding a value to a location.

A) Track per-CPU pointers
- If S is a BinaryOperator with opcode BO_Assign:
  - If the RHS is a CallExpr to this_cpu_ptr()/per_cpu_ptr():
    - Get the MemRegion of the LHS expression via getMemRegionFromExpr on the LHS Expr. If non-null, update PerCpuPtrMap[LHSRegion] = 1 (for this_cpu_ptr) or 2 (for per_cpu_ptr).
  - Else if both LHS and RHS are pointer-typed:
    - Extract MemRegion of RHS and LHS. If RHSRegion is in PerCpuPtrMap, set PerCpuPtrMap[LHSRegion] = PerCpuPtrMap[RHSRegion].
  - Do not attempt interprocedural propagation; intra-procedural aliasing via simple assignments is sufficient.

B) Detect non-atomic read-modify-write (RMW) on per-CPU fields
- If S is a CompoundAssignOperator:
  - Check if its LHS is a MemberExpr (e.g., statc->stats_updates).
  - Let Base = LHS->getBase(); If isPerCpuBaseExpr(Base, C) is true, report:
    - Create a non-fatal error node and emit "Non-atomic read-modify-write on per-CPU field; use READ_ONCE()/WRITE_ONCE()."
- If S is a UnaryOperator that is ++ or --:
  - If its sub-expression is a MemberExpr with per-CPU base (as above), report with the same message.

- If S is a BinaryOperator with opcode BO_Assign (x = y):
  - If LHS is a MemberExpr M and isPerCpuBaseExpr(M->getBase(), C):
    - Let RHS be the RHS Expr of the assignment.
    - Case 1 (RMW via x = x + ...): If rhsReadsSameField(M, RHS, C), report "Non-atomic read-modify-write on per-CPU field; use READ_ONCE()/WRITE_ONCE()."
    - Case 2 (plain store/reset, e.g., x = 0): If isConstInt(RHS, C, Out) is true (any integer constant), report "Plain write to per-CPU field; use WRITE_ONCE()."
    - Otherwise, do not report (to reduce noise).

Notes:
- We intentionally do not suppress based on READ_ONCE/WRITE_ONCE macros here because:
  - CompoundAssign and ++/-- would not appear inside WRITE_ONCE.
  - If a developer used x = READ_ONCE(x) + ..., the write is still a plain "=", which should be upgraded to WRITE_ONCE; we still warn on the write part (expected by the kernel fix).
- We do not attempt to detect bare reads without READ_ONCE to minimize false positives. We focus on the risky patterns in the patch: RMW and reset writes.

4.2) Optional: checkPreCall(const CallEvent &Call, CheckerContext &C)
Not required for detection; however, we can opportunistically record per-CPU construction when a call result is immediately used in an initialization. It is simpler to keep all tracking in checkBind, so skip this.

4.3) All other callbacks
Not needed for this checker.

5) Reporting
- On each detection in checkBind:
  - Use auto N = C.generateNonFatalErrorNode();
  - If N is null, return;
  - Create a PathSensitiveBugReport with the shared BugType and the appropriate message.
  - Add the source range of the involved MemberExpr (the per-CPU field) to the report.
  - Emit via C.emitReport(std::move(Report)).

6) Heuristics and false-positive control
- Per-CPU identification is primarily map-based (pointers created via this_cpu_ptr/per_cpu_ptr). If not in the map, we fallback to a naming heuristic on the pointee record type name containing “percpu” or ending in “_percpu”.
- We only warn on:
  - Compound assignments (+=, -=, etc.) and ++/-- on per-CPU fields.
  - Assignments to per-CPU fields that read the same field on RHS (x = x + ...) or assign an integer constant (x = 0, x = 123).
- We do not warn on other plain writes to reduce noise.
- We do not attempt to reason about cross-CPU execution; experience and naming patterns in kernel code make this heuristic precise enough for the target bug.

7) Utility functions used
- getMemRegionFromExpr to associate expressions to regions for both pointer tracking and field equality detection.
- findSpecificTypeInChildren to extract MemberExprs from complex RHSs for RMW detection.
- EvaluateExprToInt to detect plain constant stores (e.g., “= 0”).
- ExprHasName is not strictly necessary in this plan and can be omitted to keep it simple.

Summary of flow
- Track per-CPU pointer variables via assignments from this_cpu_ptr/per_cpu_ptr and propagate through simple pointer assignments (checkBind).
- On each bind:
  - If it is a compound assignment (LHS per-CPU field), warn about RMW.
  - If it is ++/-- on a per-CPU field, warn about RMW.
  - If it is a plain assignment to a per-CPU field:
    - If RHS reads the same field, warn about RMW.
    - Else if RHS is an integer constant, warn to use WRITE_ONCE.
This directly catches the exact patterns fixed by the patch: "x += ..." and "x = 0" on per-CPU fields that can be accessed by other CPUs, and guides developers to use READ_ONCE/WRITE_ONCE.
