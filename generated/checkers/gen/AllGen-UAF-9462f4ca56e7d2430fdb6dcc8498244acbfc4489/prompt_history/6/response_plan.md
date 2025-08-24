Plan

1. Program state
- No custom program state is needed. This checker is purely AST-based and looks for a structural pattern: iterating a shared Linux list and freeing entries without holding the protecting lock.

2. Callbacks to use
- checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const
  - Walk the function body to find “for”-loops that iterate a known gsm tx list and free entries, then verify that the protecting spinlock is held. Emit a report if not.

3. Detailed steps in checkASTCodeBody
- Prepare small internal helpers (simple functions in the checker):
  - getExprText(const Expr *E, CheckerContext &C): same approach as ExprHasName but returns the full text of the expression using Lexer::getSourceText.
  - isCallNamed(const CallExpr *CE, StringRef Name): return true if callee identifier equals Name.
  - containsText(const Stmt *S, StringRef Sub, CheckerContext &C): get source text for S->getSourceRange() and check if it contains Sub.
  - findFirstChildOfType<T>(const Stmt *S): a thin wrapper that repeatedly calls the provided findSpecificTypeInChildren<T>(S) until it returns nullptr or we found what we need; or just call provided findSpecificTypeInChildren<T>(S) if one instance is enough.
  - findAllChildrenCalls(const Stmt *S, SmallVectorImpl<const CallExpr*> &Out): recursively collect all CallExpr inside S (you can write a tiny recursive walker in this checker).
  - memberExprHasField(const MemberExpr *ME, StringRef FieldName): check if ME->getMemberNameInfo().getAsString() == FieldName.
  - stmtHasSpinLockAcquireOnTxLock(const Stmt *S, StringRef BaseText, CheckerContext &C): return true if S has a call to spin_lock / spin_lock_irqsave / spin_lock_bh whose first argument contains both “->tx_lock” and BaseText. Also return true if S’s source text contains “guard(” and “->tx_lock” and BaseText (to catch guard(spinlock_irqsave)(&X->tx_lock)).
  - loopOrContextHasTxLock(const ForStmt *FS, const Expr *Base, CheckerContext &C):
    - Get BaseText = getExprText(Base, C). Example: “gsm”.
    - 1) Check inside FS->getBody(): scan all CallExpr; if any matches stmtHasSpinLockAcquireOnTxLock(Stmt, BaseText, C), return true.
    - 2) Find parent CompoundStmt CS = findSpecificTypeInParents<CompoundStmt>(FS, C). If found:
      - Iterate CS->body() in order; locate the index idx where body[idx] == FS.
      - Scan statements from 0 to idx-1; if any stmtHasSpinLockAcquireOnTxLock(body[i], BaseText, C) is true, return true.
    - Otherwise, return false.

- Walk each function body’s statements and find ForStmt nodes:
  - For each ForStmt FS:
    - Identify if it iterates a gsm tx list:
      - Search FS’s subtree for a MemberExpr ME where memberExprHasField(ME, "tx_ctrl_list") or memberExprHasField(ME, "tx_data_list") is true. If none found, skip this loop.
      - Record MEList = that MemberExpr (first we find is enough). Let Base = MEList->getBase()->IgnoreParenImpCasts().
    - Confirm that the loop frees nodes (the risky part):
      - Look for a call to kfree inside the loop body: find a CallExpr CE in FS->getBody() where isCallNamed(CE, "kfree") is true. If not found, skip.
    - Optional: Tighten to linux list macro style:
      - If desired, further reduce false positives by checking source text of FS or its init/cond/inc contains “list_for_each_entry” using containsText(FS, "list_for_each_entry", C). This is optional but recommended.
    - Check whether the protecting lock is held:
      - Call loopOrContextHasTxLock(FS, Base, C).
      - If false: report a bug.

4. Bug reporting
- When loopOrContextHasTxLock returns false:
  - Create a PathSensitiveBugReport or BasicBugReport with a short message:
    - “Freeing gsm tx_* list without tx_lock; may cause use-after-free.”
  - Point the report location to FS->getForLoc() or the kfree CallExpr location (if available).
  - Emit with BR.emitReport.

5. Matching the fix pattern precisely (to reduce false positives)
- This checker is tuned for the n_gsm bug pattern:
  - Only flag loops that:
    - Reference MemberExpr with field name “tx_ctrl_list” or “tx_data_list”.
    - Call “kfree” inside the loop body.
    - Do not acquire “tx_lock” via:
      - spin_lock(&<Base>->tx_lock)
      - spin_lock_irqsave(&<Base>->tx_lock, …)
      - spin_lock_bh(&<Base>->tx_lock)
      - guard(spinlock_irqsave)(&<Base>->tx_lock)
- Ensure BaseText consistency:
  - The lock acquisition must reference the same owner as the list, i.e., both use the same base expression text (e.g., both contain “gsm->”).

6. Utility functions usage
- Use provided helpers where applicable:
  - findSpecificTypeInParents<CompoundStmt>(FS, C) to find the surrounding block to scan for preceding lock acquisition.
  - findSpecificTypeInChildren<CallExpr>(FS->getBody()) to quickly detect a kfree call inside the loop (if multiple calls are present, one is enough).
  - ExprHasName on call arguments to quickly detect “tx_lock” and BaseText presence.
- For source text checks on Stmt, replicate ExprHasName’s logic with Lexer::getSourceText over Stmt->getSourceRange().

7. Notes
- We do not track lock lifetimes or unlocking; the heuristic is simple: the presence of an acquisition call or guard on the same tx_lock in the same compound block before the loop (or inside the loop) suffices.
- This is intentionally scoped to the specific n_gsm pattern (tx_ctrl_list/tx_data_list protected by tx_lock) to keep noise low and focus on the UAF pattern fixed by adding guard(spinlock_irqsave)(&gsm->tx_lock).
