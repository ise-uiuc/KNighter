1) Program state
- No custom program state is necessary. The pattern can be detected with a single AST/code-body scan.

2) Callback functions
- Use only checkASTCodeBody. Walk the function body once, collect the structural elements (labels, gotos, frees, allocs, null-resets), and then run a set of source-order checks to decide if the retry/replay pattern is unsafe.

3) Detailed steps (checkASTCodeBody)

3.1) Collect structural facts from the function body
- Traverse the function body statements in a single pass (recursive walk) and collect:
  - Labels:
    - For each LabelStmt LS, record:
      - LabelDecl* LD = LS->getDecl()
      - Name = LD->getNameAsString()
      - Location = LS->getBeginLoc()
      - Also store a pointer to the LabelStmt itself
    - Keep a mapping: LabelDecl* -> LabelInfo {Name, Location, LabelStmt*}
  - Gotos:
    - For each GotoStmt GS:
      - Target LabelDecl* TL = GS->getLabel()
      - Source Location = GS->getGotoLoc()
      - Record vector of GotoInfo {FromLoc, TargetLabelDecl*}
  - Calls to free-like functions:
    - For each CallExpr CE with callee in {"kfree", "kvfree", "vfree"}:
      - Extract the first argument. If it is a DeclRefExpr referring to a VarDecl* V (i.e., freeing a local pointer variable), record FreeInfo {CallExpr*, VarDecl*, Loc}.
      - Also, associate this free with the closest preceding LabelStmt that dominates it textually (cleanup label). For this, pick the label with location before CE and with the greatest location among labels before CE. Map CleanupLabelDecl* -> set of freed VarDecl* and also record the exact kfree CallExpr* for each VarDecl*.
  - Assignments to NULL (reset to null):
    - For each BinaryOperator BO of kind BO_Assign where LHS is DeclRefExpr of VarDecl* V:
      - Let RHS = BO->getRHS()->IgnoreParenImpCasts().
      - Consider RHS a “null” if:
        - RHS->isNullPointerConstant(ASTContext, Expr::NPC_ValueDependentIsNotNull) is true, or
        - ExprHasName(RHS, "NULL", C) returns true, or
        - RHS is an IntegerLiteral with value 0.
      - If so, record NullResetInfo {VarDecl* V, Loc = BO->getExprLoc()}.
    - Also handle DeclStmt with an initializer for V: if initialized to a null pointer constant, record as NullResetInfo.
  - Assignments from allocation (alloc point):
    - For each assignment (BinaryOperator BO of kind BO_Assign) where LHS is DeclRefExpr of VarDecl* V and RHS is a CallExpr to an allocation function in {"kmalloc", "kzalloc", "kcalloc", "kmalloc_array", "kvmalloc", "kvzalloc", "vmalloc"}:
      - Record AllocAssignInfo {VarDecl* V, Loc = BO->getExprLoc(), CallExpr* RHS}
    - For DeclStmt with initializer equal to an allocation CallExpr for V, record similarly.
  - Replay/back-edge gotos:
    - For each GotoInfo to label La, if La.Location isBeforeInTranslationUnit(FromLoc), consider La a replay label (back-edge). Record ReplayLabels set {LabelDecl*}.

3.2) Derive candidate pairs (ReplayLabel, CleanupLabel, Var)
- For each replay label La in ReplayLabels:
  - Identify gotos to La that occur after some cleanup free section. You can later anchor the report at any goto to La after cleanup; for now just note that the function retries.
  - For each cleanup label Lb that frees some VarDecl* V (from the Cleanup map above):
    - Ensure there exists at least one goto to La whose FromLoc is after the free location of V (kfree(V)) — this confirms we retry after freeing V.

3.3) For each candidate VarDecl V, check the unsafe replay window
- Define LocA = La.Location.
- Find the first allocation for V after LocA:
  - Among AllocAssignInfo entries for V with location > LocA, take the earliest one; call its location LocAlloc.
  - If none found, treat LocAlloc as “function end” (i.e., a large sentinel location).
- Check for absence of reset to NULL between LocA and LocAlloc:
  - If there exists any NullResetInfo for V with Loc in [LocA, LocAlloc), then it is safe — skip V for this (La, Lb) pair.
- Check for early goto to cleanup before reallocation:
  - If there exists any goto to Lb with FromLoc in [LocA, LocAlloc), then the following conditions are met:
    - V is freed in cleanup (at Lb),
    - We retry (goto La) after the cleanup free,
    - Between the replay header La and the next allocation of V, there’s a path to cleanup Lb,
    - V is not reset to NULL after La,
    - Therefore, on the second iteration, a path can jump to Lb before re-allocating V and kfree(V) again (double free).
  - If so, this is the bug pattern. Record a diagnostic.

3.4) Emit a concise report
- For each detected bug:
  - Create a BasicBugReport with a short message: "Pointer freed in cleanup but not reset before retry; possible double free on replay path."
  - Choose a good location:
    - Prefer the goto to the replay label La that occurs after the cleanup (this matches the user’s fix location).
    - If multiple, pick the first such goto after the free.
  - Optionally add one or two notes (if supported) to point to:
    - The kfree(V) in the cleanup label,
    - A goto to the cleanup label between La and LocAlloc (the early error path).
  - Emit the report.

4) Heuristics and helpers
- Allocation function detection: match callee name in the set {"kmalloc", "kzalloc", "kcalloc", "kmalloc_array", "kvmalloc", "kvzalloc", "vmalloc"}.
- Free function detection: match callee name in {"kfree", "kvfree", "vfree"}.
- Null reset detection:
  - Prefer Expr::isNullPointerConstant. If unavailable, use ExprHasName(..., "NULL", C) or check IntegerLiteral zero.
- Source order comparisons:
  - Use SourceManager::isBeforeInTranslationUnit(A, B) to compare locations and to define ranges like [LocA, LocAlloc).

5) Notes to reduce false positives
- Only consider V if:
  - It is a local pointer variable (VarDecl of pointer type) declared in the function.
  - It is directly freed in the cleanup label via kfree-like calls.
- Do not rely on initializers at declaration time as “reset”; require a reset after the replay label La (this matches the kernel fix pattern).
- Require all three structural facts to hold before reporting:
  - A retry/back-edge goto to La exists after a cleanup free.
  - A goto to the cleanup label Lb exists between La and the next allocation of V.
  - No V = NULL reset between La and the next allocation of V.

6) Utility functions usage
- Use ExprHasName for robust matching of "NULL" when macros are involved.
- No need for the other provided helpers or program state in this checker.
