Plan

1. Program state
- Do not customize ProgramState. This checker can be written as an AST-only analysis with lightweight bookkeeping in checker member fields.

2. Chosen callbacks
- checkASTCodeBody: Walk each function body once to gather “per-CPU pointer” origins and their field accesses.
- checkEndAnalysis: After all bodies are seen, correlate local and remote accesses and emit diagnostics.

3. Data structures (checker member fields)
- struct VarPerCpuInfo { std::string BaseKey; enum { LocalThisCPU, RemotePerCPU } Kind; }
  - BaseKey is a stable identifier for the first argument to this_cpu_ptr()/per_cpu_ptr() (see Helpers below).
- llvm::DenseMap<const VarDecl*, VarPerCpuInfo> VarMap
  - Tracks which local variables are initialized from this_cpu_ptr()/per_cpu_ptr().
- struct AccessSite {
    const Stmt *Site;               // Statement to report (e.g., BinaryOperator, UnaryOperator, or the MemberExpr itself)
    std::string BaseKey;            // Same base key as in VarMap
    std::string FieldName;          // The per-CPU field name (e.g., "stats_updates")
    bool IsWrite;                   // true if write or read-modify-write (+=, =, ++/--)
    bool IsRead;                    // true if read occurs (used in rvalue)
    bool IsAtomic;                  // true if guarded by READ_ONCE/WRITE_ONCE
    bool IsRemote;                  // true if derived from per_cpu_ptr
  }
- llvm::SmallVector<AccessSite, 64> AllSites
  - Append an AccessSite for each field access of a tracked per-CPU pointer.

4. What to detect and when to report
- Remote access rule (per_cpu_ptr):
  - Any read of a per-CPU field not guarded by READ_ONCE is a bug.
  - Any write of a per-CPU field not guarded by WRITE_ONCE is a bug.
  - Report these immediately at the end (checkEndAnalysis) for every AccessSite with IsRemote && !IsAtomic && (IsRead || IsWrite).
- Local-remote race rule:
  - If a per-CPU field BaseKey.FieldName is accessed remotely anywhere in TU (remote existence), then local (this_cpu_ptr) accesses to the same field must be atomic as well.
  - Report non-atomic local reads or writes only if there exists at least one remote access for the same BaseKey.FieldName (atomic or not).
  - This matches the fix: local update site needed READ_ONCE/WRITE_ONCE because the remote side also touches the same field.

5. checkASTCodeBody: per-function collection
- Build per-function maps then merge into global member containers (VarMap for variables within this function only; AllSites append-only).
- Steps:
  1) Find variables initialized from this_cpu_ptr/per_cpu_ptr
     - Walk the body recursively and record:
       - VarDecl with initializer as a CallExpr whose callee name is “this_cpu_ptr” or “per_cpu_ptr”.
       - BinaryOperator assignments where LHS is a pointer variable and RHS is a CallExpr to “this_cpu_ptr”/“per_cpu_ptr”.
     - For each such place:
       - Extract the first argument expression of the call (for per_cpu_ptr, the first argument; for this_cpu_ptr, its only argument).
       - Build BaseKey (see Helpers).
       - Insert into VarMap: VarDecl* -> {BaseKey, LocalThisCPU or RemotePerCPU}.
  2) Track simple aliases (optional but recommended):
     - If “T *p2 = p1;” or “p2 = p1;” and p1 exists in VarMap, then record p2 with the same VarPerCpuInfo.
     - Only do same-function alias tracking (no interprocedural).
  3) Collect field accesses:
     - For each MemberExpr “X->Field” or “(*X).Field”:
       - If its base is a DeclRefExpr to a VarDecl in VarMap, then it is a per-CPU field access.
       - Determine FieldName from the MemberExpr’s member declaration identifier.
       - Determine read/write kind:
         - If parent is a BinaryOperator with isAssignmentOp() and this MemberExpr is on the LHS: IsWrite = true. If it’s a CompoundAssignOperator: IsWrite = true and IsRead = true.
         - If parent is a UnaryOperator with ++/--: IsWrite = true and IsRead = true.
         - Otherwise, treat as rvalue read: IsRead = true.
       - Determine if atomic:
         - Climb to nearest parent CallExpr using findSpecificTypeInParents<CallExpr>(...) and check:
           - If ExprHasName(ParentCall, "READ_ONCE", C), then treat as atomic read.
           - If ExprHasName(ParentCall, "WRITE_ONCE", C), then treat as atomic write.
         - For compound situations (e.g., p->f += v), if not wrapped by both READ_ONCE and WRITE_ONCE forms, consider non-atomic. For simplicity, if the MemberExpr is not in a READ_ONCE/WRITE_ONCE call context, set IsAtomic = false.
       - Skip benign cases:
         - If the MemberExpr type is volatile-qualified, skip (assume handled).
       - Create AccessSite:
         - Site = the most relevant parent stmt for reporting:
           - If assignment, use the BinaryOperator stmt.
           - If unary ++/--, use the UnaryOperator.
           - Else use the MemberExpr itself.
         - BaseKey from the owning VarDecl’s VarPerCpuInfo.
         - FieldName from MemberExpr.
         - IsAtomic as determined, IsRemote = (VarPerCpuInfo.Kind == RemotePerCPU).
       - Append to AllSites.
- Note: Use ExprHasName and get source text as needed (see Helpers).

6. checkEndAnalysis: correlate and report
- Build a set RemoteTouched: Set of “BaseKey.FieldName” that have any remote access (atomic or not).
- Emit diagnostics:
  - Remote non-atomic:
    - For each site S where S.IsRemote && !S.IsAtomic:
      - If S.IsWrite: “Remote per-CPU write without WRITE_ONCE”
      - Else if S.IsRead: “Remote per-CPU read without READ_ONCE”
  - Local-remote race:
    - For each site S where !S.IsRemote && !S.IsAtomic && (S.IsRead || S.IsWrite):
      - If (S.BaseKey + "." + S.FieldName) is in RemoteTouched:
        - Report: “Non-atomic access to per-CPU field also accessed remotely; use READ_ONCE/WRITE_ONCE”
- Use std::make_unique<BasicBugReport> with a short message, attach S.Site as the location.
- Only one report per site; do not deduplicate beyond that for simplicity.

7. Helpers and matching details
- Identify this_cpu_ptr/per_cpu_ptr calls:
  - In AST, get callee’s IdentifierInfo and compare names.
- Extract BaseKey:
  - Compute a stable, comparable key using the source text of the first argument expression of this_cpu_ptr/per_cpu_ptr:
    - Use SourceManager and LangOptions similarly to ExprHasName to get Lexer::getSourceText(CharSourceRange::getTokenRange(Arg->getSourceRange())).
    - Use that string as BaseKey (e.g., “memcg->vmstats_percpu”).
- Determine atomic guard:
  - For READ_ONCE/WRITE_ONCE, inspect the nearest parent CallExpr:
    - If ExprHasName(ParentCall, "READ_ONCE", C) => atomic read.
    - If ExprHasName(ParentCall, "WRITE_ONCE", C) => atomic write.
  - If both read and write are needed (e.g., “+=”), require both; in practice, if the MemberExpr is not wrapped by either macro, IsAtomic = false.
- Determine read/write:
  - Use findSpecificTypeInParents to locate BinaryOperator or UnaryOperator parents.
  - BinaryOperator bo:
    - If bo.isAssignmentOp() and MemberExpr is LHS: IsWrite = true.
    - If isa<CompoundAssignOperator>: IsWrite = true, IsRead = true.
  - UnaryOperator uo with ++/--: IsWrite = true, IsRead = true.
  - Otherwise: IsRead = true (rvalue use).
- Skip volatile fields:
  - If MemberExpr->getType().isVolatileQualified(): ignore.

8. What this catches (mapping to the target pattern)
- Remote plain access: per_cpu_ptr(..., cpu) -> statc->stats_updates = 0; is flagged (no WRITE_ONCE).
- Local plain update in hot path: this_cpu_ptr(...), statc->stats_updates += abs(val); is flagged only if there also exists any remote access to the same BaseKey.FieldName somewhere in the TU. Message advises to use READ_ONCE/WRITE_ONCE.
- This mirrors the patch: add READ_ONCE for local read, WRITE_ONCE for local reset, and WRITE_ONCE for remote reset.
