```
Plan: Detect unsynchronized cross-CPU accesses to per-CPU fields (e.g., stats_updates) without READ_ONCE/WRITE_ONCE

1) Program State
   - Use a single Program State map to track whether a pointer value is a per-CPU pointer and whether it is local (this_cpu_ptr) or remote (per_cpu_ptr with explicit cpu).
     - REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrKindMap, const MemRegion*, unsigned)
       - Kind: 1 = LocalThisCPU (from this_cpu_ptr), 2 = RemotePerCPU (from per_cpu_ptr with a cpu expression not smp_processor_id()).
   - Checker-level (non-state) cache:
     - SmallPtrSet<const FieldDecl*, 16> RemotePerCpuFields
       - Fields observed accessed via remote per_cpu_ptr in this TU (read or write). Used to decide when to warn on local RMW that races with remote access.

   No other custom traits are required.

2) Callbacks and Logic

   A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) — central logic
      Goals:
      - Track origin of pointer variables (from this_cpu_ptr/per_cpu_ptr).
      - Propagate aliasing of tracked pointers.
      - Detect writes to per-CPU fields (assignment / compound assignment).
      - Report two bug kinds:
        - Remote per-CPU write without WRITE_ONCE.
        - Local per-CPU RMW without READ/WRITE_ONCE when the same field is also accessed remotely.

      Implementation steps:

      1. Track pointer origin on assignment:
         - If S is a BinaryOperator (use findSpecificTypeInParents<BinaryOperator>(S, C)), with opcode BO_Assign and RHS is a CallExpr:
           - Extract callee name.
           - If name == "per_cpu_ptr" and it has two args:
             - Determine if the 2nd arg is smp_processor_id():
               - Use ExprHasName on the second argument to check it contains "smp_processor_id".
               - If NOT smp_processor_id, mark LHS region as RemotePerCPU (2).
               - If smp_processor_id, mark as LocalThisCPU (1) (rare but safe).
           - If name == "this_cpu_ptr":
             - Mark LHS region as LocalThisCPU (1).
         - If RHS is a DeclRefExpr pointing to a tracked region:
           - Propagate PerCpuPtrKindMap from RHS region to LHS region (alias propagation).
         - If RHS is a MemberExpr whose base region is tracked:
           - Propagate PerCpuPtrKindMap from that base to LHS region (handles assignments like statc = statc->parent).

      2. Detect and classify writes to per-CPU fields:
         - If S has a BinaryOperator B (assignment or compound):
           - Let LHS be B->getLHS()->IgnoreParenImpCasts().
           - If LHS is not a MemberExpr, return.
           - Get the MemberExpr ME and its FieldDecl FD = cast<FieldDecl>(ME->getMemberDecl()).
           - Determine per-CPU pointer kind for the base of ME:
             a) Try getMemRegionFromExpr(ME->getBase(), C), lookup in PerCpuPtrKindMap.
             b) If not found in the map, fallback: search for a CallExpr inside ME->getBase() (findSpecificTypeInChildren<CallExpr>(ME->getBase())).
                - If callee name == "per_cpu_ptr" and second arg does NOT have "smp_processor_id", treat as RemotePerCPU (2).
                - If callee name == "this_cpu_ptr", treat as LocalThisCPU (1).
           - If still unknown, stop (we only warn for known per-CPU pointers).

         2.1 Remote write check (WRITE_ONCE required):
           - If kind == RemotePerCPU (2) AND B is a simple assignment (BO_Assign):
             - Evaluate RHS constant using EvaluateExprToInt; if it evaluates to 0 (typical flush case), this is a cross-CPU zeroing write.
             - Ensure the statement is not using WRITE_ONCE:
               - Use ExprHasName on B (or S) with "WRITE_ONCE".
               - If absent, add FD to RemotePerCpuFields and report:
                 - BugType: "Cross-CPU per-CPU write without WRITE_ONCE"
                 - Message: "Cross-CPU write to per-CPU field without WRITE_ONCE"
           - Regardless of value, since it’s a remote write, add FD to RemotePerCpuFields for later local-RMW checks.

         2.2 Local RMW check (READ/WRITE_ONCE required when field is remotely accessed):
           - If kind == LocalThisCPU (1) AND operation is a compound assignment (e.g., +=, -=, |=, etc.; use B->isCompoundAssignmentOp()):
             - If FD is in RemotePerCpuFields:
               - Ensure statement text does not include READ_ONCE or WRITE_ONCE (ExprHasName(B, "READ_ONCE") or "WRITE_ONCE"):
                 - If both absent, report:
                   - BugType: "RMW on per-CPU field without READ/WRITE_ONCE"
                   - Message: "RMW of per-CPU field also accessed cross-CPU; use READ_ONCE/WRITE_ONCE"
           - (Optional) For ++/-- on fields: If needed, handle UnaryOperator in a similar way (see note below).

      Notes:
      - This approach intentionally focuses on two high-signal cases from the patch:
        - Remote zeroing writes via per_cpu_ptr(..., cpu) must use WRITE_ONCE.
        - Local fast path RMW (+=) must switch to READ_ONCE snapshot + WRITE_ONCE when the field is also accessed cross-CPU elsewhere.
      - It avoids heavy interprocedural data flow by tracking per-CPU pointer kinds in ProgramState and recording which fields have been seen remotely in a checker-level set.

   B) checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) — mark remote reads
      - If IsLoad is true and S contains a MemberExpr ME:
        - Determine if ME->getBase() refers to a RemotePerCPU (as in A.2 fallback or via PerCpuPtrKindMap).
        - If yes, add the FieldDecl to RemotePerCpuFields (so that later local RMW to the same field can be flagged).
      - No direct reporting here.

   C) Optional (if desired): Handle ++/-- on fields
      - In checkBind, the binding for ++/-- often still appears as a BinaryOperator internally; but to be safe:
        - Use findSpecificTypeInParents<UnaryOperator>(S, C) to detect pre/post inc/dec.
        - If operand is a MemberExpr and base is LocalThisCPU and FD is in RemotePerCpuFields, and neither READ_ONCE nor WRITE_ONCE is present in the source text for S:
          - Report with the same "RMW of per-CPU field ..." message.

3) Helper routines (internal to checker)
   - isPerCpuPtrCall(const CallExpr*): returns true if callee name is "per_cpu_ptr".
   - isThisCpuPtrCall(const CallExpr*): returns true if callee name is "this_cpu_ptr".
   - isSmpProcessorIdExpr(const Expr*): returns true if ExprHasName(expr, "smp_processor_id").
   - getPerCpuKindFromBaseExpr(const Expr* Base, CheckerContext &C):
     - Try PerCpuPtrKindMap via getMemRegionFromExpr.
     - If not present, look for CallExpr in children and classify as LocalThisCPU or RemotePerCPU as described above.

4) Bug reporting
   - Use two BugType singletons stored in the checker:
     - "Cross-CPU per-CPU write without WRITE_ONCE"
     - "RMW on per-CPU field without READ/WRITE_ONCE"
   - For each violation:
     - auto N = C.generateNonFatalErrorNode();
     - If (!N) return;
     - Create PathSensitiveBugReport with the corresponding BugType and short message:
       - Remote write: "Cross-CPU write to per-CPU field without WRITE_ONCE"
       - Local RMW: "RMW of per-CPU field also accessed cross-CPU; use READ_ONCE/WRITE_ONCE"
     - Attach the relevant expression (the BinaryOperator) as the location of interest.

5) Simplifications and rationale
   - We avoid complex alias graphs; pointer origin is tracked when assigned from calls or from already tracked pointers, and propagated through member-based reassignments like statc = statc->parent.
   - We key warnings off of:
     - Remote writes via per_cpu_ptr(..., cpu) without WRITE_ONCE.
     - Local compound RMW via this_cpu_ptr when the same field is known to be accessed cross-CPU elsewhere, without READ_ONCE/WRITE_ONCE.
   - We rely on ExprHasName to recognize presence of READ_ONCE/WRITE_ONCE in the source text, which is sufficient for this kernel macro pattern.

6) Minimal callbacks used
   - checkBind: main tracking and reporting.
   - checkLocation: to mark remote-read fields so that later local RMW can be flagged.

```
