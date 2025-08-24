1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion *, bool)
  - Tracks which pointer regions are known to point to per-CPU storage (true).
  - We only need a boolean tag; no additional state is required.
- No other traits/maps needed. We will propagate this tag through simple pointer assignments/binds.


2) Helper logic

- isPerCpuGetterName(StringRef N):
  - Return true if N equals "this_cpu_ptr" or "per_cpu_ptr".
- getCallName(const CallExpr *CE):
  - If CE->getDirectCallee() exists, return its Identifier name.
  - Else empty string.
- rhsContainsPerCpuGetter(const Stmt *S, CheckerContext &C):
  - Use findSpecificTypeInChildren<CallExpr>(S).
  - If found, return true if isPerCpuGetterName(getCallName(CE)) is true OR ExprHasName(CE, "this_cpu_ptr", C) OR ExprHasName(CE, "per_cpu_ptr", C) is true (covers inline/macro wrappers).
- isStatsUpdatesME(const MemberExpr *ME):
  - Return true if ME->getMemberNameInfo().getAsString() equals "stats_updates".
- getBaseRegionOfMember(const MemberExpr *ME, CheckerContext &C):
  - BaseE = ME->getBase()->IgnoreParenImpCasts()
  - return getMemRegionFromExpr(BaseE, C)
- inOnceMacroContext(const Stmt *S, CheckerContext &C, bool IsStore):
  - We want to suppress warnings if access is annotated.
  - Walk up to a reasonable parent Stmt (e.g., the nearest CallExpr parent or the full statement containing S) using findSpecificTypeInParents<CallExpr>(S, C). If found, check:
    - IsStore: ExprHasName(CallExpr, "WRITE_ONCE", C)
    - !IsStore: ExprHasName(CallExpr, "READ_ONCE", C)
  - If no CallExpr parent, also directly check the source text of S via ExprHasName(S, "WRITE_ONCE"/"READ_ONCE", C) as a best-effort fallback.
  - Return true if any of the checks match; false otherwise.
- isPerCpuBase(const Expr *Base, CheckerContext &C):
  - R = getMemRegionFromExpr(Base, C)
  - Query PerCpuPtrMap for R. If found true, return true.


3) Callback: checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const

Goal: learn which pointers are per-CPU.

- Identify destination region:
  - If Loc is a loc::MemRegionVal, get DestR = Loc.getAsRegion().
  - Only proceed if DestR is a VarRegion or a FieldRegion of pointer type.
- Case A: RHS originates from per-CPU getter
  - If rhsContainsPerCpuGetter(S, C) is true:
    - State' = State->set<PerCpuPtrMap>(DestR, true)
    - C.addTransition(State')
- Case B: Propagate tag from another pointer
  - If Val is loc::MemRegionVal and SrcR = Val.getAsRegion():
    - If State says SrcR is in PerCpuPtrMap as true:
      - State' = State->set<PerCpuPtrMap>(DestR, true)
      - C.addTransition(State')
- Otherwise do nothing.
Notes:
- This handles both declarations with initializers and assignments because CSA calls checkBind for both.
- This also captures statc = this_cpu_ptr(...); and propagates through statc = statc->parent; if the RHS has a region (often MemberExpr yields a region for the field), we will mark the LHS when applicable.


4) Callback: checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const

Goal: detect plain reads/writes on per-CPU stats_updates without READ_ONCE/WRITE_ONCE.

- Fast-fail if Loc has no region: return.
- Find a MemberExpr that corresponds to the accessed location:
  - ME = findSpecificTypeInChildren<MemberExpr>(S). If null, return.
  - If !isStatsUpdatesME(ME), return.
- Verify base is a per-CPU pointer:
  - BaseE = ME->getBase()->IgnoreParenImpCasts()
  - If !isPerCpuBase(BaseE, C), return.
- Macro annotation check:
  - If inOnceMacroContext(S, C, /*IsStore=*/!IsLoad) returns true, then annotated; return.
- Decide whether to warn:
  - We primarily flag writes (IsLoad == false). These include:
    - Direct assignment: statc->stats_updates = 0;
    - Compound updates: statc->stats_updates += abs(val);
  - Optionally, you may also warn on loads (IsLoad == true) for the same field if desired; to keep it minimal and precise, restrict to stores.
- If IsLoad == false and not annotated:
  - Generate a non-fatal error node: auto N = C.generateNonFatalErrorNode();
  - If N is null, return.
  - Create and emit a PathSensitiveBugReport with a short message:
    - Title: "Non-atomic per-CPU field write"
    - Message: "Non-atomic write to per-CPU 'stats_updates'; use WRITE_ONCE (and READ_ONCE for paired reads)."
    - Add the source range of the MemberExpr as the primary range.
    - C.emitReport(std::move(R)).


5) Optional: checkPreCall(const CallEvent &Call, CheckerContext &C) const

(Only if you also want to catch unsafe reads passed directly to atomics; otherwise skip for simplicity.)

- Inspect each argument of Call:
  - If an argument contains a MemberExpr to 'stats_updates' with a per-CPU base and inOnceMacroContext == false for read:
    - Warn similarly but with load-specific message ("Non-atomic read to per-CPU 'stats_updates'; use READ_ONCE").


6) Callback selection rationale

- checkBind: simplest and reliable way to identify and propagate “per-CPU pointer” knowledge from this_cpu_ptr/per_cpu_ptr to local variables and their aliases.
- checkLocation: directly tells us when a program reads or writes a memory location; we filter to stores to the specific member, and verify per-CPU provenance, and lack of READ/WRITE_ONCE annotation.
- No need for additional callbacks (ASTDecl/ASTCodeBody) or custom evalCall/assume, keeping the checker small and focused.


7) Bug report

- Use std::make_unique<PathSensitiveBugReport>.
- Category: "Concurrency"
- Short message examples:
  - For stores: "Non-atomic write to per-CPU 'stats_updates'; use WRITE_ONCE."
  - If you also implement reads: "Non-atomic read of per-CPU 'stats_updates'; use READ_ONCE."
- One report per offending access; no path notes necessary beyond the location range of the MemberExpr or full assignment statement.
