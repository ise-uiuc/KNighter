Plan

1) Program state
- No custom program state is necessary. This checker is purely structural (AST-based) and detects a control-flow pattern (label + goto retry + unconditional kfree in cleanup) that can cause a double free across iterations.

2) Callbacks to use
- checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR)
  We will scan the function body AST once to find:
  - The cleanup label that unconditionally frees a pointer p via kfree(p).
  - A retry goto that jumps back to an earlier label (the “restart” label).
  - At least one early goto to the cleanup label that can occur before p is reinitialized or reallocated on the next iteration.
  - Absence of p = NULL either just after the free (before the retry goto) or right after the restart label (before any early goto to cleanup).

3) Detailed implementation (checkASTCodeBody)

3.1) Collect structural facts from the AST
- Pre-scan the FunctionDecl’s body (Stmt subtree) and collect the following with source locations (use SourceManager::isBeforeInTranslationUnit for ordering):
  a) All LabelStmt nodes:
     - Record: LabelStmt* L, StringRef Name, SourceLocation Loc.
  b) All GotoStmt nodes:
     - Record: GotoStmt* G, SourceLocation Loc, LabelStmt* Target (via G->getLabel()).
  c) All cleanup frees: For each LabelStmt L, search inside its labeled subtree for kfree/kvfree:
     - Use findSpecificTypeInChildren<CallExpr>(L) plus a linear recursive descent to collect all CallExpr under L.
     - For each CallExpr CE where callee identifier is "kfree" or "kvfree":
       - If the first argument is a DeclRefExpr to a VarDecl* P (pointer variable), record a candidate cleanup free site:
         CleanupFree = { VarDecl* P, LabelStmt* CleanupLabel L2, CallExpr* FreeCall, SourceLocation FreeLoc }.
       - We treat this as “unconditional free in cleanup” (the call is directly in the labeled block).
  d) All assignments to pointer P:
     - While traversing, collect BinaryOperator nodes with isAssignmentOp():
       - If LHS is a DeclRefExpr to some VarDecl* P (pointer), record an assignment event:
         Assign = { VarDecl* P, SourceLocation Loc, RHSKind }
         where RHSKind is:
           - ResetToNull if RHS is a null pointer constant:
             Detect with RHS->IgnoreImpCasts():
               - IntegerLiteral == 0, or
               - GNUNullExpr, or
               - CXXNullPtrLiteralExpr (if C++).
           - OtherWrite otherwise (including assignments from kmalloc/kzalloc/kcalloc/etc.).
     - Optionally include initializations on DeclStmt (VarDecl with Init) as assignment events with that init’s SourceLocation.
  e) Optionally record “allocation writes” to P:
     - For assignments P = call(...), if callee is "kmalloc"/"kzalloc"/"kcalloc"/"krealloc", classify as OtherWrite. (We don’t need to distinguish, just not ResetToNull.)

3.2) Identify the restart-goto pattern per pointer P
- For each CleanupFree {P, L2, FreeLoc}:
  1) Find a “restart goto”:
     - A GotoStmt G_restart whose SourceLocation G_restart.Loc is after FreeLoc
       and whose target label L1 has SourceLocation L1.Loc before FreeLoc.
     - This matches the pattern: cleanup (free) happens, then “if (should_retry) goto restart_label;”.
     - If no such G_restart exists, skip this CleanupFree (no retry loop).
  2) Check safety fix 1: reset to NULL after free and before retry
     - Look for any assignment event for P with ResetToNull and with source location in (FreeLoc, G_restart.Loc). If found, this iteration resets p to NULL before re-entering the loop; skip (safe).
  3) Check safety fix 2: reset to NULL near the restart label
     - Let RestartLoc = L1.Loc.
     - Find the earliest assignment event W to P that occurs after RestartLoc.
       - If no such assignment exists, set WLoc = +infinity (no assignment).
       - If the earliest assignment W is ResetToNull, we consider this iteration safe against early gotos (p becomes NULL before any other modification); continue only if earliest is not ResetToNull.
  4) Check for an early goto to cleanup before P is written after restart
     - Look for any GotoStmt G_early that targets L2 (cleanup label) with source location in (RestartLoc, WLoc). If any exists, that means on the next iteration, there is a path that can go to cleanup before p is reset/reallocated. Since cleanup unconditionally frees p and we already freed p in the previous iteration, this is a possible double free.
     - If found, and step 2/3 did not find a ResetToNull, report a bug.

Notes:
- If there are multiple restart gotos after free, it’s enough to find any one that makes the pattern true.
- If there are multiple early gotos to L2, any one in (RestartLoc, WLoc) suffices.

3.3) Bug reporting
- For each detected issue:
  - Create a BugType “Possible double free across replay/retry loop”.
  - Emit a BasicBugReport at the free call location FreeLoc (or at the restart goto location G_restart.Loc).
  - Message: “Pointer freed in cleanup then retried without resetting to NULL; early goto can double free.”
  - Add a source range highlight on the kfree(...) call and, if helpful, on the restart goto.
  - Keep the message short and clear as requested.

4) Heuristics and robustness
- Callee recognition:
  - Compare callee identifier string with "kfree" and "kvfree".
- Label names:
  - Not required for correctness, but you can include label names in notes if desired.
- Assignment to NULL detection:
  - Prefer direct AST matching as above (IntegerLiteral 0, GNUNullExpr, CXXNullPtrLiteralExpr).
  - If you later migrate this logic to a path-sensitive callback (e.g., checkBind), you can use EvaluateExprToInt for more cases.
- Source order:
  - Use SourceManager::isBeforeInTranslationUnit to compare SourceLocations reliably.
- Multiple pointers:
  - Run the above logic per pointer P discovered in cleanup frees. Report each offending P independently.

5) Optional refinements (if needed later)
- Consider also treating “p = NULL” immediately in cleanup after kfree(p) as a safety fix (step 2 already covers this).
- Recognize more free-like functions if present in the target codebase (e.g., vfree). Adjust callee matching accordingly.
- Extend null-detection to also recognize explicit casts to (void *)0, etc.

Summary
- No program state is needed.
- A single AST-body pass (checkASTCodeBody) finds the specific label/goto retry pattern plus unconditional kfree in cleanup and absence of p = NULL reset before re-entering the retry loop.
- The detection is conservative and tailored to the target bug pattern from the patch: unconditional kfree in a common cleanup label, a retry goto to a restart label, and possible early goto to cleanup before reallocation/reset, causing double free across iterations.
