1) Program state customizations

- REGISTER_MAP_WITH_PROGRAMSTATE(WaitRetSymToContainer, SymbolRef, const MemRegion*)
  - Maps the symbolic return value of wait_for_completion_timeout() to the “context” pointer (the container of the completion field) used in that call.

- REGISTER_SET_WITH_PROGRAMSTATE(TimeoutContainers, const MemRegion*)
  - Set of context pointers that are known (along the current path) to be in the timeout branch (i.e., wait_for_completion_timeout() returned 0).

- REGISTER_SET_WITH_PROGRAMSTATE(EnqueuedWorkContainers, const MemRegion*)
  - Context pointers whose work item has been queued/scheduled (queue_work(), queue_delayed_work(), schedule_work(), etc.).

- REGISTER_SET_WITH_PROGRAMSTATE(SafeToFreeContainers, const MemRegion*)
  - Context pointers that have had their work canceled/flushed (cancel_work_sync(), cancel_delayed_work_sync(), flush_work(), flush_delayed_work()), meaning the work item is guaranteed not running anymore and the context is safe to free.

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer-to-pointer aliases for the context pointer to recognize kfree(ptr_alias) is the same as kfree(original_context).


2) Helper predicates and extractors

- isWaitTimeout(const CallEvent&):
  - Returns true if callee is "wait_for_completion_timeout".

- isWorkQueueSubmit(const CallEvent&):
  - Returns true if callee is one of {"queue_work", "queue_work_on", "schedule_work", "queue_delayed_work", "queue_delayed_work_on"}.

- isWorkCancelOrFlush(const CallEvent&):
  - Returns true if callee is one of {"cancel_work_sync", "cancel_delayed_work_sync", "flush_work", "flush_delayed_work"}.

- isFreeCall(const CallEvent&):
  - Returns true if callee is one of {"kfree", "kvfree", "vfree"}.

- getContextRegionFromMemberAddressArg(const Expr*):
  - For an argument that is typically &ctx->member (UnaryOperator '&' of MemberExpr), return the MemRegion of the base expression (ctx). Handle both arrow/dot MemberExpr. Use getMemRegionFromExpr on the MemberExpr base. Return null if not matched.

- getContextRegionFromExpr(const Expr*):
  - For expressions like ctx (DeclRefExpr), return its MemRegion using getMemRegionFromExpr.

- resolveAlias(const MemRegion*, ProgramStateRef):
  - Walk PtrAliasMap to find the ultimate root context region for a pointer. If not found, return the same input region.


3) Callbacks and their logic

A) checkPostCall

- wait_for_completion_timeout
  - Extract the first argument and derive the context region:
    - Arg0 is expected to be &ctx->compl. Use getContextRegionFromMemberAddressArg(Arg0) to get ctxRegion. If it fails, do nothing.
  - Obtain the symbolic return value of the call: Call.getReturnValue().getAsSymbol()
  - If both retSym and ctxRegion exist, set WaitRetSymToContainer[retSym] = ctxRegion.

- Work submission (queue_work*, schedule_work)
  - Identify the work item argument:
    - For queue_work*, relevant pointer is the work_struct pointer usually &ctx->work_field (2nd param for queue_work, 1st for schedule_work). Use getContextRegionFromMemberAddressArg to get ctxRegion.
  - If ctxRegion found, add ctxRegion to EnqueuedWorkContainers.

- Work cancel/flush (cancel_work_sync, cancel_delayed_work_sync, flush_work, flush_delayed_work)
  - Extract ctxRegion from the single work argument (&ctx->work_field) using getContextRegionFromMemberAddressArg.
  - If found:
    - Add ctxRegion to SafeToFreeContainers.
    - Optionally remove from EnqueuedWorkContainers (not strictly required, but helps reduce false positives).

B) evalAssume

- Purpose: recognize when the current path assumes wait_for_completion_timeout() returned 0 (timeout).
- If Cond contains or equals a SymbolRef S that exists in WaitRetSymToContainer:
  - Let ctxRegion = WaitRetSymToContainer[S].
  - Interpret the branch:
    - If Assumption == false, treat this as Sym == 0 branch (timeout). Add ctxRegion to TimeoutContainers in the returned state for that branch.
    - If Assumption == true, treat this as Sym != 0 (no timeout). Ensure ctxRegion is removed from TimeoutContainers in that branch’s state (if present).
- Handle SymIntExpr and logical-not cases generically:
  - If Cond is a SymExpr involving only S (e.g., S, !S, S==0, S!=0), the core will pass both branches through evalAssume; using the Assumption boolean as above is sufficient.

C) checkPreCall

- Free calls (kfree/kvfree/vfree)
  - Extract the pointer argument region P via getContextRegionFromExpr(Call.getArgExpr(0)).
  - Compute R = resolveAlias(P).
  - If all hold:
    - R is in TimeoutContainers (we’re on the branch where wait_for_completion_timeout timed out),
    - R is in EnqueuedWorkContainers (we actually queued the work for this context),
    - R is not in SafeToFreeContainers (we did not cancel/flush the work before freeing),
  - Then report: this is the risky pattern “free context after timeout while worker may still use it” (possible UAF).

- Optional: If you want to be stricter, also check that there is no completion_done() usage for this context before the free (but this usually appears in the worker, not here, so skip for simplicity).

D) checkBind

- Track pointer aliasing:
  - If Loc is a region of a pointer variable L and Val is a Loc SVal of another pointer region R:
    - Record PtrAliasMap[L] = resolveAlias(R).
  - If Val is unknown/undefined, skip.
  - If Val is a call return binding or a direct reference to an existing context pointer, treat similarly (if you can obtain its region as Loc).

E) Optional: checkBranchCondition (lightweight AST-path fallback)

- As a supplemental heuristic (in case evalAssume cannot connect): detect conditions of the form:
  - if (!ret) {... kfree(ctx) ...} where ret was bound from wait_for_completion_timeout(&ctx->compl, ...), or
  - if (wait_for_completion_timeout(&ctx->compl, ...)) ... else { ... kfree(ctx) ... }
- You can detect the presence of wait_for_completion_timeout in the condition using findSpecificTypeInChildren<CallExpr>(), and if so, remember the enclosing IfStmt* and its ctxRegion into a temporary set. Then, when a free call is visited within the else branch subtree, and the ctxRegion matches, issue the same report. This is optional; prefer the path-sensitive evalAssume approach above.


4) Bug reporting

- Create a BugType once, e.g., "Work context freed on timeout".
- When the kfree is about to happen in checkPreCall and all three conditions match (TimeoutContainers contains R, EnqueuedWorkContainers contains R, SafeToFreeContainers does not contain R), generate a non-fatal error node and emit a PathSensitiveBugReport with a concise message:
  - "Freeing work context after completion timeout; worker may still use it (possible UAF)."
- Optionally add path notes:
  - At the wait_for_completion_timeout call: "wait_for_completion_timeout may have timed out here".
  - At the queue_work call: "work item for this context was queued here".


5) Notes on minimizing false positives

- Require that the context was actually enqueued via a work queue call before the wait/timeout (EnqueuedWorkContainers).
- Suppress the report if the work was canceled/flushed before the free (SafeToFreeContainers).
- If you want an even stricter check, only report if the completion argument to wait_for_completion_timeout is &ctx->compl (ExprHasName(MemberExpr, "compl") can be used to ensure we’re tracking a completion field typical for this pattern).


6) Summary of chosen callbacks

- checkPostCall:
  - Track wait_for_completion_timeout return symbol -> context pointer.
  - Record enqueued work contexts (queue_work*, schedule_work).
  - Record cancel/flush to mark contexts as safe-to-free.

- evalAssume:
  - Mark/unmark the current path as the timeout branch for a specific context.

- checkPreCall:
  - On kfree/kvfree/vfree, if context is being freed on a timeout branch while work is still enqueued and not canceled/flushed, report.

- checkBind:
  - Track pointer-to-pointer aliasing so frees via aliases are recognized.

- (Optional) checkBranchCondition:
  - AST fallback to detect inline if (wait_for_completion_timeout(...)) patterns and free in else-branch if path-sensitive approach is insufficient.
