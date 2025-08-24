1) Program state
- No custom program state is necessary. This checker is best implemented as an AST-only analysis within each function and then cross-function correlation at the end of the analysis.
- Use checker data members to accumulate:
  - A map FieldKey -> SmallVector<const Stmt*> for local non-atomic RMW sites (LocalRMWSites).
  - A map FieldKey -> SmallVector<const Stmt*> for remote plain-write sites (RemoteWriteSites).

2) Callback functions and implementation steps
- checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR)
  Goal: For each function body, detect:
    a) Variables that point to percpu objects (this_cpu_ptr or per_cpu_ptr).
    b) Non-atomic RMW of fields through this_cpu_ptr-based pointers.
    c) Plain writes to the same fields through per_cpu_ptr-based pointers.

  2.1 Local bookkeeping within a function
  - Define an enum PerCpuKind { Unknown, ThisCPU, RemoteCPU }.
  - Maintain a map VarKind: const VarDecl* -> PerCpuKind.
  - Maintain simple aliasing: on pointer copies, propagate PerCpuKind to the target variable.
  - Helper: FieldKey builder for a MemberExpr on pointer-to-record, returning a stable key such as "<RecordName>.<FieldName>" (e.g., "memcg_vmstats_percpu.stats_updates"). Use:
    - ME->getMemberDecl()->getNameAsString() for field name.
    - For the base expression’s type, if it’s pointer to record, use the pointee record decl name.

  2.2 Detect percpu pointer acquisition and propagate kinds
  - Traverse the function’s body with a DFS or RecursiveASTVisitor.
  - For VarDecl with initializer or BinaryOperator “=” where LHS is a DeclRefExpr to a VarDecl V:
    - If RHS is a CallExpr and callee name is "this_cpu_ptr":
      - VarKind[V] = ThisCPU.
    - If RHS is a CallExpr and callee name is "per_cpu_ptr":
      - VarKind[V] = RemoteCPU.
      - No need to special-case the second argument; any per_cpu_ptr indicates named-CPU access (possibly remote).
    - If RHS is a DeclRefExpr to a VarDecl U and VarKind[U] is known:
      - VarKind[V] = VarKind[U]. (alias propagation)
  - For BinaryOperator “=” where both sides are variables (pointer-to-record):
    - Apply the same alias propagation (VarKind[LHSVar] = VarKind[RHSVar] when RHSVar kind known).

  2.3 Detect local non-atomic RMW on percpu fields (ThisCPU pointers)
  - CompoundAssignOperator:
    - If LHS is a MemberExpr (ME) and the base of ME is a DeclRefExpr to VarDecl V with VarKind[V] == ThisCPU:
      - This is a non-atomic RMW (+=, -=, |=, &=, etc). Build FieldKey for ME and record the statement in LocalRMWSites[FieldKey].
  - BinaryOperator “=”:
    - If LHS is a MemberExpr (ME) whose base is V with VarKind[V] == ThisCPU:
      - Check if RHS reads the same field: the RHS contains a MemberExpr referencing the same FieldDecl and same base VarDecl V. Use a simple recursive walk over RHS to find a MemberExpr with the same FieldDecl and base VarDecl.
      - If so, this is an explicit RMW pattern “field = field op value”. Record in LocalRMWSites[FieldKey].
    - Do not attempt to special-case READ_ONCE/WRITE_ONCE here; if they were used, the pattern wouldn’t be a compound assignment nor a direct “field = field + …” on the plain field.

  2.4 Detect remote plain writes on percpu fields (RemoteCPU pointers)
  - BinaryOperator “=”:
    - If LHS is a MemberExpr (ME) and the base of ME is a DeclRefExpr to VarDecl V with VarKind[V] == RemoteCPU:
      - This is a plain write to a percpu field in a remote context. Build FieldKey and record the statement in RemoteWriteSites[FieldKey].
  - Optional: Skip if the assignment is an atomic intrinsic or a known macro wrapper call. In practice, when WRITE_ONCE is used, this will not appear as a simple binary “=” assignment, so no extra filtering is usually required.

  Notes:
  - You can use ExprHasName(CallExpr, "this_cpu_ptr", C) and ExprHasName(CallExpr, "per_cpu_ptr", C) to match callee names when walking the AST.
  - For matching the same field in “field = field op ...”, compare:
    - MemberExpr->getMemberDecl() pointers for equality.
    - The DeclRefExpr of the base variable for equality.

- checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng)
  Goal: Emit reports only when both sides of the race pattern are present.

  Steps:
  - For each FieldKey that appears in LocalRMWSites and also appears in RemoteWriteSites:
    - For each Stmt* S in LocalRMWSites[FieldKey], emit a report:
      - Message: "Non-atomic RMW on per-CPU field also written from remote CPU; use READ_ONCE/WRITE_ONCE."
      - Use BasicBugReport with a custom BugType owned by the checker.
      - Attach S as the primary location.
      - Optionally add an extra note on one of the RemoteWriteSites[FieldKey] statements: "Remote write occurs here."

3) Heuristics and filters to reduce false positives
- Only consider MemberExpr through pointer-to-record where the pointer VarDecl was identified as ThisCPU (from this_cpu_ptr) for RMW detection and RemoteCPU (from per_cpu_ptr) for remote writes.
- Do not report if only LocalRMWSites or only RemoteWriteSites exist for a given field; require the intersection to be non-empty to approximate “also accessed from other CPUs”.
- Ignore cases where the left-hand side write is clearly done through atomic APIs (e.g., calls like atomic_add/atomic64_add, or macros that won’t appear as plain assignments).
- Because READ_ONCE/WRITE_ONCE usage does not yield plain compound assignments or plain “= field + ...” on the raw field in the AST, those safe cases naturally do not match.

4) Reporting
- Use a single BugType: "Per-CPU non-atomic RMW race".
- Emit one BasicBugReport per unique RMW site in the intersection.
- Keep the message short:
  - "Non-atomic RMW on per-CPU field raced with remote write; wrap with READ_ONCE/WRITE_ONCE."
- Provide a secondary note at a representative remote write site when available to help users locate the other side of the race.

5) Utility functions used
- ExprHasName(...) for identifying calls to this_cpu_ptr and per_cpu_ptr.
- findSpecificTypeInChildren(...) can be used to search a MemberExpr inside RHS when checking “field = field + ...”.
- findSpecificTypeInParents(...) can be used to find the closest enclosing Stmt if needed for precise report locations.
