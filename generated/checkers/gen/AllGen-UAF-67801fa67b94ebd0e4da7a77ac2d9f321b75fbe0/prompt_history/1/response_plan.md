Plan

1) Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(PublishedMap, const MemRegion*, const Stmt*)
  - Key: the MemRegion of the pointer variable that is published into an ID registry (e.g., xa_alloc’s 3rd parameter).
  - Value: the Stmt of the publish call (used for bug location/notes).
- REGISTER_SET_WITH_PROGRAMSTATE(ReportedSet, const MemRegion*)
  - Tracks regions we have already reported on to avoid duplicate diagnostics on different paths/statements.

2) Helper utilities
- bool isIoctlFunction(const CheckerContext &C)
  - Return true if the current function name contains “ioctl” (case-insensitive). This limits the checker to ioctl-like creation paths where the pattern is relevant.
- Optional: bool isCreateLike(const CheckerContext &C)
  - If desired to further reduce false positives, also allow names containing “create” in addition to “ioctl”.
- Optional: Small allowlist/denylist of publish APIs
  - Recognize publish APIs and the index of the pointer argument:
    - xa_alloc: pointer arg index = 2
    - xa_alloc_cyclic: pointer arg index = 2
    - idr_alloc: pointer arg index = 1
    - idr_alloc_u32: pointer arg index = 1
    - idr_alloc_cyclic: pointer arg index = 1
  - Implement a helper:
    - bool isPublishCall(const CallEvent &Call, unsigned &PtrParamIndex)
      - Returns true and sets PtrParamIndex when the callee name matches any known publish API.
- const MemRegion* getVarRegionFromArg(const Expr *E, CheckerContext &C)
  - Use getMemRegionFromExpr(E, C). If it is non-null and corresponds to a local VarRegion (i.e., a simple DeclRefExpr to a pointer variable), use it as the key in PublishedMap.
- StringRef getVarNameForRegion(const MemRegion *R)
  - If R is a VarRegion, return the VarDecl’s name (used in matching and better diagnostics).
- bool exprUsesPublishedVar(const Expr *E, const MemRegion *Published, CheckerContext &C)
  - Detect whether expression E uses the published pointer variable.
  - Prefer AST-based checks: if E contains a MemberExpr whose base is a DeclRefExpr bound to the same VarDecl as the Published MemRegion, return true. Also check ArraySubscriptExpr base and UnaryOperator deref (*) with base DeclRefExpr.
  - As fallback, use ExprHasName(E, getVarNameForRegion(Published), C) and ensure it’s a pointer dereference or member access (look for MemberExpr base or deref operator).
- bool isPublishCallItself(const CallEvent &Call, const MemRegion *Published, CheckerContext &C)
  - If the callee is a publish API and the pointer parameter matches the Published MemRegion, this is the publish call itself; do not report on it.

3) checkPostCall
Goal: detect the moment the object is published into the ID registry and mark it in state.
- If not isIoctlFunction(C) return.
- If isPublishCall(Call, PtrParamIndex) is true:
  - Get the pointer argument expression ArgE = Call.getArgExpr(PtrParamIndex).
  - Get the pointer variable region: PtrR = getVarRegionFromArg(ArgE, C). If null, ignore (we only handle simple pointer variables to minimize noise).
  - Add (PtrR -> Call.getOriginExpr() or Call.getStmt()) to PublishedMap.
  - Do not report here; just mark as published.

4) checkBind
Goal: after publish, any write to fields/deref of the published pointer (e.g., q->field = ...) indicates “publish not last”.
- If PublishedMap empty, return.
- Extract an assignment BinaryOperator from S using findSpecificTypeInChildren<BinaryOperator>(S). If not found or not an assignment, return.
- Let LHS = BO->getLHS().
- For each (PublishedRegion -> PubStmt) in PublishedMap:
  - If PublishedRegion already in ReportedSet, continue.
  - If exprUsesPublishedVar(LHS, PublishedRegion, C) is true and the use is a member access or deref (i.e., writing through q, not just rebinding the pointer q itself):
    - Report a bug:
      - Message: “ID allocated before final initialization; publish must be last to avoid UAF.”
      - Primary location: the current statement S (the post-publish write).
      - Add a note at PubStmt: “Object published here (xa_alloc/id[r])”.
    - Insert PublishedRegion into ReportedSet.

5) checkPreCall
Goal: after publish, any call that uses the published pointer (passing q or q->something) indicates “publish not last”.
- If PublishedMap empty, return.
- For each (PublishedRegion -> PubStmt) in PublishedMap:
  - If PublishedRegion already in ReportedSet, continue.
  - If isPublishCallItself(Call, PublishedRegion, C), continue (skip the publish call itself).
  - Iterate over Call arguments:
    - If exprUsesPublishedVar(ArgE, PublishedRegion, C):
      - Report a bug:
        - Message: “Object used after publishing into ID registry; publish must be last in ioctl.”
        - Primary location: current call statement.
        - Add a note at PubStmt: “Object published here (xa_alloc/id[r])”.
      - Insert PublishedRegion into ReportedSet.
      - Break.

6) Optional: checkLocation
Goal: catch post-publish memory writes via pointer derefs not seen in checkBind (e.g., compound assignments or implicit stores).
- If PublishedMap empty, return.
- If IsLoad is false (store):
  - Try to get a relevant LHS/Expr from S (e.g., via findSpecificTypeInChildren<MemberExpr/UnaryOperator/ArraySubscriptExpr>(S)).
  - If exprUsesPublishedVar(thatExpr, PublishedRegion, C) for any PublishedRegion not yet reported:
    - Report as in checkBind.

7) State cleanup
- checkEndFunction: Clear all per-function tracking by returning State->remove(PublishedMap) and State->remove(ReportedSet). The analyzer will discard state anyway when the function ends; this keeps it explicit.

8) Reporting details
- Use std::make_unique<PathSensitiveBugReport> with a dedicated BugType (e.g., “Publish-before-finalization (UAF risk)”).
- Keep the message short and clear:
  - “ID allocated before final initialization; publish must be last to avoid UAF.”
- Attach the publish call site (PubStmt) as an additional note/source range, and the misuse site (store/call) as the primary location.

9) Summary of the rule enforced
- Within ioctl-like functions, after a call to xa_alloc/idr_alloc that publishes an object pointer:
  - No writes through the object pointer (q->..., *q, q[i]) are allowed.
  - No further function calls passing the object pointer (q or q->...) are allowed.
  - In short: the publish must be the last operation in the creation ioctl (except writing out the new ID to the user args and returning). The checker warns on any post-publish use of the object pointer.
