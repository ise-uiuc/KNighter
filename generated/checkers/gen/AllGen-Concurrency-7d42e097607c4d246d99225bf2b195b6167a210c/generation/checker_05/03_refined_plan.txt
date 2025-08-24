Plan for a CSA checker: Detect freeing of a queued-work context on timeout while worker still uses/frees it without completion_done check (potential UAF/double-free)

1) Program state customization
- Do not use path-sensitive program state. This pattern can be detected reliably with an AST-body pass plus light cross-function bookkeeping.
- Maintain lightweight checker-level caches:
  - DenseMap<const FunctionDecl*, WorkerBodyInfo> WorkerInfoMap:
    - hasCompletionDone: bool
    - hasUseOrFree: bool (true if calls complete/complete_all or kfree)
    - firstUseOrFreeLoc: SourceLocation (for reporting)
  - DenseSet<const FunctionDecl*> RiskyWorkers: worker functions referenced by callers that queue work and may free the context after wait_for_completion_timeout (timeout branch).
  - Optional: DenseMap<const FunctionDecl*, std::string> WorkerNameMap for user-friendly messages.

2) Callback choices and implementation details

- checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR)
  Perform all the analysis in this callback in two roles:
  A) For caller (submitter) functions: discover “at-risk” worker callbacks.
  B) For worker functions: precompute whether they contain completion_done and whether they use/free the context.

  2.A) Submitter-side scan to find risky worker callbacks
  - Preconditions: Only handle FunctionDecl with hasBody().
  - Traverse the function body once (simple recursive walk over Stmts and Exprs) and collect:
    - INIT_WORK-like calls:
      - Identify CallExpr callee by name among: "INIT_WORK", "__INIT_WORK", "INIT_WORK_ONSTACK", "init_work" (include a few kernel variants).
      - Get first argument (addr-of work field): expect UnaryOperator '&' applied to MemberExpr referencing a field whose name contains "work" (e.g., "work", "reset_work").
      - Extract the “owner” base Expr from the MemberExpr (IgnoreParenImpCasts). If it is a DeclRefExpr or a MemberExpr whose base is DeclRefExpr, record the owner Decl (VarDecl/ParmVarDecl) as OwnerDecl.
      - Get second argument (worker function pointer). If it is a DeclRefExpr to a FunctionDecl, record OwnerDecl -> WorkerDecl in a local map OwnerToWorker.
    - wait_for_completion_timeout calls:
      - Identify CallExpr callee name: "wait_for_completion_timeout".
      - First arg should be a pointer to a completion. Extract base owner Decl from first arg similarly (expect UnaryOperator '&' applied to MemberExpr).
      - Record a vector WaitSites[OwnerDecl].push_back(SourceLocation).
    - kfree calls:
      - Identify CallExpr callee name: "kfree" (include "kvfree" as variant).
      - First arg expression (IgnoreParenImpCasts) should ideally reference the same owner Decl from above. If it is a DeclRefExpr or MemberExpr rooted at the same owner Decl, record FreeSites[OwnerDecl].push_back(SourceLocation).
  - After the scan:
    - For each OwnerDecl that has a recorded WorkerDecl:
      - If it also has at least one wait_for_completion_timeout site and at least one kfree site, and the kfree location is after the wait call (compare SourceManager locations), consider the submitter frees context after timeout.
      - If the function contains an if-condition or logical negation around wait_for_completion_timeout, you do not need to fully interpret it. The existence of both the wait and a subsequent kfree(owner) is sufficient to consider the pattern at risk (heuristic, reduces complexity).
      - For each such OwnerDecl, add the associated WorkerDecl to RiskyWorkers.
      - If WorkerInfoMap already has an entry for that WorkerDecl with hasUseOrFree = true and hasCompletionDone = false, issue a report now (see reporting below).

  2.B) Worker-side scan to see if completion_done is checked and if the context is used/freed
  - If D is a FunctionDecl with a body, collect:
    - hasCompletionDone: whether the function body contains a CallExpr whose callee name is "completion_done".
    - hasUseOrFree: whether there exists a CallExpr with callee name in {"kfree", "kvfree", "complete", "complete_all"}.
      - If yes, record the first such CallExpr’s SourceLocation as firstUseOrFreeLoc for diagnostic pointing.
    - Store WorkerBodyInfo into WorkerInfoMap[D].
    - If D is already in RiskyWorkers and hasUseOrFree is true and hasCompletionDone is false, emit a report at firstUseOrFreeLoc.

- Helper logic used in checkASTCodeBody
  - getOwnerDeclFromAddrOfMember(Expr* E):
    - E should be the expression for "&owner->field".
    - Strip ImplicitCasts/ParenCasts.
    - Expect UnaryOperator Kind == UO_AddrOf. Take its subExpr.
    - Expect MemberExpr. Take its base expression, strip casts/parentheses.
    - If base is DeclRefExpr, return cast<VarDecl/ParmVarDecl>(getDecl()) as owner key.
    - If base is a MemberExpr chain that ultimately roots at a DeclRefExpr, return that root Decl as owner key.
    - If not recognizable, return null and skip.
  - occursAfter(SourceLocation A, SourceLocation B, SourceManager &SM):
    - Compare SM.isBeforeInTranslationUnit(B, A) to check if A is textually after B.
  - isCalleeNamed(CallExpr* CE, StringRef Name):
    - If FunctionDecl *FD = CE->getDirectCallee(), compare FD->getNameAsString() with Name.
    - For macros that expand to functions, getDirectCallee still generally works on the expanded call.

3) Reporting
- When conditions hold (worker is in RiskyWorkers, hasUseOrFree is true, and hasCompletionDone is false), create a report:
  - Use BasicBugReport with a concise message:
    - "Worker may use/free context after submitter timeout; missing completion_done() check"
  - Emit the report at firstUseOrFreeLoc inside the worker function.
  - Optionally include a note or description to hint the fix: "Guard complete()/kfree() with completion_done() to coordinate ownership after timeout."

4) Notes and simplifications
- This checker uses a robust heuristic:
  - It links submitter’s owner pointer between INIT_WORK(&owner->work, worker), wait_for_completion_timeout(&owner->...), and kfree(owner).
  - It marks the associated worker as risky without path-sensitive return-value analysis.
- We do not require a full dominance check in the worker: the presence of any completion_done() call in the worker function is treated as safe enough; otherwise, any call to complete()/kfree() in that worker is flagged when the worker is at risk.
- Function and member names to detect:
  - Worker init: "INIT_WORK", "__INIT_WORK", "INIT_WORK_ONSTACK", "init_work". The first argument’s member name should contain "work".
  - Wait with timeout: "wait_for_completion_timeout". First argument is "&owner->...".
  - Worker usage/free: "complete", "complete_all", "kfree", "kvfree".
  - Safety check: "completion_done".
- The checker only relies on checkASTCodeBody (simplest and sufficient). No need for path-sensitive callbacks or custom program state.
