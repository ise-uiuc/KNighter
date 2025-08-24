Plan: Detect freeing a work item’s context in the scheduler’s timeout path after wait_for_completion_timeout, which can race with the worker still using the context

1) Program State
- No custom program states are required. We will implement a local, AST-based checker working within a single function body to keep it simple and robust.

2) Chosen callbacks
- Use checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR):
  - We will analyze each function body once, scan its statements, and recognize:
    - A wait_for_completion_timeout() check in an if-condition (directly or via a temporary/ret variable).
    - The branch that corresponds to the timeout case.
    - A free of the same context pointer (kfree(ctx)) in the timeout branch, or unconditionally after the if-statement (both branches).
  - Emit a bug if freeing occurs on the timeout path (definite) or is unconditional after the timeout test (suspicious).

3) High-level detection strategy
- Target AST shape:
  - queue_work(..., &ctx->work) [optional]
  - ret = wait_for_completion_timeout(&ctx->compl, tmo); or if (wait_for_completion_timeout(&ctx->compl, tmo)) ...
  - if (ret) / if (!ret) / if (ret == 0) / if (ret != 0) / if (wait_for_completion_timeout(...)) / if (!wait_for_completion_timeout(...)) / if (wait_for_completion_timeout(...) == 0) ...
  - timeout branch code
  - kfree(ctx) in timeout branch (definite bug) OR kfree(ctx) unconditionally after the if-statement (suspicious bug)
- Rationale:
  - If ctx is freed on timeout, the worker (which still references ctx to signal completion or use other fields) can dereference freed memory → UAF.
  - The patch’s fix uses completion_done(&ctx->compl) and “free-only-in-one-place” ownership separation.

4) Core helpers to implement (local to the checker)
- isWaitForCompletionTimeoutCall(const CallExpr *CE):
  - Return true if callee name is "wait_for_completion_timeout".
- getCtxVarFromCompletionArg(const Expr *Arg) -> const VarDecl*:
  - Arg is the first argument to wait_for_completion_timeout (e.g., &ctx->compl).
  - Strategy:
    - Strip implicit casts/paren.
    - Find a DeclRefExpr in children (using findSpecificTypeInChildren<DeclRefExpr>(Arg)).
    - Return its VarDecl (this is the base “ctx” variable).
  - Note: This works for typical “&ctx->done/compl” and “&reset_data.compl” cases; we match the first DeclRefExpr as the base.
- getDeclRefVar(const Expr *E) -> const VarDecl*:
  - Given an expression (e.g., kfree(ctx)), find the DeclRefExpr in it (findSpecificTypeInChildren<DeclRefExpr>) and return its VarDecl.
- conditionClassifyTimeoutBranch(const Expr *CondExpr, const VarDecl* &CtxVD, const VarDecl* &RetVD, AnalysisManager &Mgr) -> enum { TimeoutIsThen, TimeoutIsElse, Unknown }:
  - Normalize CondExpr via IgnoreParenImpCasts.
  - Handle forms:
    - Direct call: if (wait_for_completion_timeout(&ctx->compl, ...))
      - CtxVD = getCtxVarFromCompletionArg(Call->getArg(0))
      - TimeoutIsElse (nonzero => success, zero => timeout).
    - Negated direct call: if (!wait_for_completion_timeout(...))
      - CtxVD as above; TimeoutIsThen.
    - Binary compare with zero/null: wait_for_completion_timeout(...) == 0 => TimeoutIsThen; != 0 => TimeoutIsElse. Same if LHS is a DeclRef (ret).
    - DeclRef variable: if (ret) => TimeoutIsElse; if (!ret) => TimeoutIsThen.
      - RetVD is the DeclRef’s VarDecl.
  - If condition uses a variable ret, we must resolve which ctx that ret came from. We do this with a preceding-statement scan (below).
- findRetVarToCtxMap(CompoundStmt *Body):
  - While scanning statements top-down within the CompoundStmt, for each assignment:
    - ret = wait_for_completion_timeout(&ctx->compl, ...);
    - Record a mapping RetVarToCtx: VarDecl* ret -> VarDecl* ctx.
  - Keep this simple map local to the function body scan.
- findTimeoutBranchForIf(const IfStmt *IfS, const VarDecl *CtxFromCond, const VarDecl *RetFromCond, const llvm::DenseMap<const VarDecl*, const VarDecl*> &RetVarToCtx, AnalysisManager &Mgr) -> pair<const Stmt*, const VarDecl*>:
  - Use conditionClassifyTimeoutBranch to determine which branch is timeout.
  - If condition referenced a ret variable, look up RetVarToCtx to get CtxVD; if missing, return unknown.
  - Return the Stmt* corresponding to timeout branch (IfS->getThen() or IfS->getElse()) and the CtxVD.
- hasFreeOfCtx(const Stmt *S, const VarDecl *CtxVD, AnalysisManager &Mgr) -> bool:
  - Recursively traverse S’s children to find a CallExpr to “kfree”, “kvfree”, or “vfree”.
  - For each such Call, extract first argument’s VarDecl via getDeclRefVar and compare pointer equality with CtxVD.
  - Return true on first match.
- findUnconditionalFreeAfterIf(const IfStmt *IfS, const VarDecl *CtxVD) -> bool:
  - Get parent CompoundStmt via findSpecificTypeInParents<CompoundStmt>(IfS, Ctx placeholder).
  - Scan the CompoundStmt’s children to find the IfS; then inspect subsequent statements (until next control-flow barrier like return/break) for a top-level kfree(ctx).
  - If found, report as suspicious unconditional free.
  - Keep it simple: stop when encountering another IfStmt/ReturnStmt; only check immediate successive statements.
- Optional aid: ExprHasName for fallback matching if DRE extraction fails (e.g., compare textual base names in “&reset_data.compl” and “kfree(reset_data)”).

5) Implementation in checkASTCodeBody
- For each function with a body:
  - Obtain the top CompoundStmt (body).
  - Build RetVarToCtx map:
    - Walk statements; when you encounter a BinaryOperator assignment whose RHS is a CallExpr to wait_for_completion_timeout, record mapping retVar -> ctxVar via getCtxVarFromCompletionArg.
  - Walk statements again to find IfStmt nodes:
    - For each IfStmt:
      - Use findTimeoutBranchForIf to figure out timeout branch and ctxVar.
      - If unknown (cannot resolve ctx), skip.
      - Check if the timeout branch exists and contains kfree(ctx) using hasFreeOfCtx. If yes, emit a report:
        - Title: Freeing work context on timeout may cause UAF
        - Message: ctx freed in timeout path after wait_for_completion_timeout; worker may still use it. Use completion_done() and free in one place.
      - Else, check if there is an unconditional free after the IfStmt using findUnconditionalFreeAfterIf. If yes, emit a lower-confidence report:
        - Title: Possibly freeing work context regardless of wait outcome
        - Message: ctx freed unconditionally after wait_for_completion_timeout; ensure timeout ownership is handled by worker (e.g., via completion_done()).
- Reporting:
  - Create a BugType once per checker (e.g., “Workqueue timeout UAF”).
  - Use PathSensitiveBugReport or BasicBugReport (Basic is sufficient here).
  - Attach a range on the kfree call’s argument for clarity if possible.

6) Notes and heuristics to reduce false positives
- Only warn for kfree() of the same ctx variable that appears as the base in &ctx->compl.
- Only trigger on wait_for_completion_timeout to limit scope to the intended synchronization primitive.
- Prefer the “definite” case (free in timeout branch). The “unconditional after if” case should be marked as "suspicious" (optional severity tag in message) to avoid noise.

7) Utility function usage
- findSpecificTypeInChildren:
  - To extract DeclRefExpr from the first argument of wait_for_completion_timeout and from kfree arguments.
- findSpecificTypeInParents:
  - To locate the parent CompoundStmt of an IfStmt to search for unconditional frees after it.
- ExprHasName:
  - As a fallback when DeclRef extraction fails; check that both the wait arg and kfree arg contain the same base identifier text (e.g., “reset_data”).

8) Edge cases handled
- Condition forms:
  - Direct call, negated call, ret variable, negated ret, compare to 0 or NULL.
- Free functions:
  - kfree, kvfree, vfree (extendable).
- The ctx may have different identifier names (we key by VarDecl identity, not by string, when possible).

This plan keeps the checker simple (single AST callback), precise for the most error-prone pattern (free-on-timeout), and mirrors the fix pattern (use completion_done() and free only in one place).
