Plan

1. Program state customization
- REGISTER_SET_WITH_PROGRAMSTATE(PerCpuPtrSet, const MemRegion*)
  - Purpose: Track pointer-valued MemRegions that are known per-CPU pointers (returned from this_cpu_ptr/per_cpu_ptr or derived/aliased from them).

2. Helper predicates and utilities
- isPerCpuGetter(CallExpr/CallEvent):
  - Return true when the callee name is one of: "this_cpu_ptr", "per_cpu_ptr", "raw_cpu_ptr", "per_cpu_ptr_no_check", "get_cpu_ptr".
- isWriteOnceContext(const Expr *E, CheckerContext &C):
  - Find parent CallExpr via findSpecificTypeInParents<CallExpr>(E, C).
  - Return true if ExprHasName(ParentCallExpr, "WRITE_ONCE", C) is true.
- baseIsPerCpuPtr(const Expr *Base, CheckerContext &C):
  - If Base is a CallExpr and isPerCpuGetter(CallExpr) -> true.
  - Else, get MemRegion of Base via getMemRegionFromExpr(Base, C) and check if it exists in PerCpuPtrSet.
- isZero(const Expr *E, CheckerContext &C):
  - Use EvaluateExprToInt to see if it evaluates to integer zero.

3. Callbacks and their logic

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
- Goal 1: Propagate per-CPU pointer aliases.
  - Determine LHS region: const MemRegion *LHSReg = Loc.getAsRegion().
  - If LHSReg is null, return.
  - If Val is a region SVal and ValReg ∈ PerCpuPtrSet, then add LHSReg to PerCpuPtrSet.
  - Else, try to discover RHS patterns from AST:
    - If S is a DeclStmt with an initializer, or a BinaryOperator with isAssignmentOp, get the RHS Expr RE.
    - If RE contains a CallExpr CE (use findSpecificTypeInChildren<CallExpr>(S)) and isPerCpuGetter(CE):
      - Mark LHSReg ∈ PerCpuPtrSet (LHS type should be a pointer).
    - Else if RE is a DeclRefExpr or MemberExpr whose base region (for MemberExpr: ME->getBase()) is in PerCpuPtrSet and RE’s type is a pointer:
      - Mark LHSReg ∈ PerCpuPtrSet.
    - This covers cases like “p = this_cpu_ptr(...);” and “statc = statc->parent;”.
- Goal 2: Detect suspicious RMW on per-CPU fields (+=, -=, ++, --).
  - From S, find a MemberExpr ME that is being written (use findSpecificTypeInChildren<MemberExpr>(S)).
  - Validate ME is the LHS:
    - Find ancestor CompoundAssignOperator CAO = findSpecificTypeInParents<CompoundAssignOperator>(ME, C). If CAO and CAO->getLHS()->IgnoreParenImpCasts() == ME->IgnoreParenImpCasts():
      - Let Base = ME->getBase()->IgnoreParenImpCasts().
      - If baseIsPerCpuPtr(Base, C) is true:
        - Report bug: "RMW on per-CPU field without READ_ONCE/WRITE_ONCE".
    - Else, handle increment/decrement:
      - Find ancestor UnaryOperator UO = findSpecificTypeInParents<UnaryOperator>(ME, C).
      - If UO exists and UO is one of pre/post inc/dec, and UO->getSubExpr()->IgnoreParenImpCasts() == ME->IgnoreParenImpCasts():
        - If baseIsPerCpuPtr(Base, C) is true:
          - Report bug: "RMW on per-CPU field without READ_ONCE/WRITE_ONCE".
- Goal 3: Detect suspicious plain reset to zero on per-CPU fields.
  - From S, find BinaryOperator BO = findSpecificTypeInParents<BinaryOperator>(ME, C).
  - If BO exists, BO->isAssignmentOp() is true, and BO is not a compound assignment:
    - If BO->getLHS()->IgnoreParenImpCasts() == ME->IgnoreParenImpCasts():
      - Let RHS = BO->getRHS()->IgnoreParenImpCasts().
      - If isZero(RHS, C) is true and isWriteOnceContext(ME, C) is false:
        - Let Base = ME->getBase()->IgnoreParenImpCasts().
        - If baseIsPerCpuPtr(Base, C) is true:
          - Report bug: "Plain store to per-CPU field; use WRITE_ONCE".

Notes:
- The compound assignment path (Goal 2) intentionally flags any per-CPU field "+=", "-=", "++", "--" as unsafe RMW. This matches the target pattern, where the fix is to split into READ_ONCE + compute + WRITE_ONCE.
- The plain reset path (Goal 3) flags "field = 0" on per-CPU fields unless wrapped by WRITE_ONCE.
- For macros READ_ONCE/WRITE_ONCE, use ExprHasName on the parent CallExpr to suppress false positives. This is robust enough for the Linux-style macros.

B) Optional: checkPostCall(const CallEvent &Call, CheckerContext &C) const
- Not necessary for detection, but can be used to opportunistically tag temporary expressions as per-CPU pointers if they are immediately used:
  - If Call callee name matches isPerCpuGetter and the return value is bound to a MemRegion (rare), mark that region in PerCpuPtrSet.
- This is optional because checkBind already propagates from assignments and handles bases that are calls in LHS MemberExpr.

4. Bug reporting
- Maintain two BugType singletons:
  - BT_RMW: "Per-CPU RMW without READ_ONCE/WRITE_ONCE"
  - BT_PlainStore: "Per-CPU plain store without WRITE_ONCE"
- When a violation is found:
  - auto N = C.generateNonFatalErrorNode(); if (!N) return;
  - Create PathSensitiveBugReport with the specific BugType.
  - Message:
    - For RMW: "RMW on per-CPU field without READ_ONCE/WRITE_ONCE"
    - For plain zero store: "Plain store to per-CPU field; use WRITE_ONCE"
  - Highlight the MemberExpr source range.
  - Emit the report.

5. Coverage of the target pattern in the patch
- In memcg_rstat_updated:
  - Detect "statc->stats_updates += abs(val)" as RMW on per-CPU field → report.
  - Detect "statc->stats_updates = 0" as plain store → report unless wrapped in WRITE_ONCE.
- In mem_cgroup_css_rstat_flush:
  - Detect "statc->stats_updates = 0" as plain store → report unless wrapped in WRITE_ONCE.
- The checker recognizes 'statc' as per-CPU pointer via:
  - "statc = this_cpu_ptr(...)" assignment in memcg_rstat_updated.
  - "statc = per_cpu_ptr(..., cpu)" assignment in mem_cgroup_css_rstat_flush.
  - Propagates per-CPU property across "statc = statc->parent".

6. Simplifications and robustness choices
- We do not attempt to prove cross-CPU remote access; we conservatively consider any per-CPU pointer field update as potentially racy if it uses plain RMW/reset.
- We rely on ExprHasName to detect READ_ONCE/WRITE_ONCE wrappers via parent CallExpr textual name matches.
- We use EvaluateExprToInt to robustly recognize RHS literal zero in resets.
- We use findSpecificTypeInParents/Children to tie the MemberExpr to the correct operator node for accurate classification.
