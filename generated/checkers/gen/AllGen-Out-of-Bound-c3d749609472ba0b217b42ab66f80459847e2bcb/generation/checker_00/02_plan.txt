1) Program state
- No custom program state is needed. This checker is a targeted, mostly-syntactic pattern matcher over loop constructs and array subscripts.

2) Callbacks and implementation steps

Step A: Use checkASTCodeBody to analyze each function body
- Rationale: We need to correlate a loop bound expression (containing dc->caps.max_links) with array subscripts inside the loop body that index per-CRTC arrays (e.g., crtcs[], secure_display_ctxs[]). This correlation is easiest with an AST traversal over the function body.
- Implementation:
  - Build a lightweight AST visitor that runs within checkASTCodeBody for the current Decl with a statement body.
  - The visitor performs two passes (or one pass with two tasks):
    1) Collect per-CRTC-sized locals created via kcalloc/kmalloc_array.
    2) Find loops whose conditions use dc->caps.max_links and whose bodies index per-CRTC arrays with the same induction variable.

Step B: Collect per-CRTC-sized local arrays/pointers (within checkASTCodeBody)
- Purpose: Recognize locals sized by num_crtc or AMDGPU_MAX_CRTCS so indexing those with max_links is suspicious.
- How:
  - Traverse all statements to find:
    - Variable declarations with initializer being a call to kcalloc/kmalloc_array, e.g.:
      - Type *p = kcalloc(Count, ElemSize, Flags);
      - Type *p = kmalloc_array(Count, ElemSize, Flags);
    - Assignments where LHS is a variable and RHS is a call to kcalloc/kmalloc_array.
  - Extract:
    - The callee name (match “kcalloc” or “kmalloc_array”).
    - The “Count” expression (first arg for kcalloc/kmalloc_array).
  - Heuristically mark the variable as “per-CRTC sized” if the Count expression’s source text indicates:
    - ExprHasName(Count, "num_crtc", C) OR
    - ExprHasName(Count, "AMDGPU_MAX_CRTCS", C)
  - Store in a local map (e.g., llvm::DenseMap<const VarDecl*, bool>) available during the current checkASTCodeBody invocation: PerCrtcSizedLocals[varVD] = true.

Step C: Detect suspicious loops (ForStmt and WhileStmt) with max_links bound (within checkASTCodeBody)
- Purpose: Find loops where the condition involves max_links and inside the body we index per-CRTC arrays with the induction variable.
- How:
  - For each ForStmt and WhileStmt:
    - Let CondE be the loop condition expression.
    - If !ExprHasName(CondE, "max_links", C), skip.
    - Optional precision filter: also require ExprHasName(CondE, "dc->caps", C) to better match dc->caps.max_links.
  - Determine candidate induction variables used in the condition:
    - Traverse CondE and collect all DeclRefExpr that refer to integral VarDecls (commonly the induction variable, e.g., i or link).
    - For each VarDecl* candidateVD, search the loop body for ArraySubscriptExpr whose index is this exact DeclRefExpr to candidateVD (IgnoreParenImpCasts).
  - For each ArraySubscriptExpr indexed by candidateVD:
    - Retrieve the base expression (ASE->getBase()->IgnoreParenImpCasts()).
    - Classify the base as per-CRTC if any holds:
      - ExprHasName(Base, "crtcs", C) AND ExprHasName(Base, "mode_info", C). This matches adev->mode_info.crtcs[i].
      - ExprHasName(Base, "secure_display_ctxs", C). This matches adev->dm.secure_display_ctxs[i] and local secure_display_ctxs[i].
      - Base is a DeclRefExpr to a local VarDecl that is flagged in PerCrtcSizedLocals as true.
    - Optional precision filter: if both CondE and Base contain “adev” (ExprHasName(CondE,"adev",C) and ExprHasName(Base,"adev",C)) then prefer to report; this ties both sides to the same device object and reduces false positives.
  - If any per-CRTC base is indexed by candidateVD and CondE contains max_links, trigger a report.

Notes:
- This approach catches:
  - for (i = 0; i < adev->dm.dc->caps.max_links; i++) { secure_display_ctxs[i] ... }
  - for (i = 0; i < adev->dm.dc->caps.max_links; i++) { adev->mode_info.crtcs[i] ... }
- It avoids flagging arrays that are intentionally sized by max_links (e.g., hpd_rx_offload_wq) because we restrict to well-known per-CRTC arrays by name and locals sized by num_crtc/AMDGPU_MAX_CRTCS.

Step D: Reporting
- When a match is found in Step C:
  - Create a BugType once, e.g., static std::unique_ptr<BugType> BT(new BugType(this, "Per-CRTC array indexed by max_links", "Memory Error"));
  - Emit a BasicBugReport with message:
    - “Possible out-of-bounds: loop bound uses dc->caps.max_links but indexes a per-CRTC array; use adev->mode_info.num_crtc.”
  - Anchor the report location at:
    - Preferably the ArraySubscriptExpr using candidateVD (highlights the actual indexing).
    - Optionally add a note on the loop condition containing max_links.

Step E: Utility functions used
- Use ExprHasName to detect key names inside expressions:
  - "max_links", "dc->caps", "secure_display_ctxs", "crtcs", "mode_info", "AMDGPU_MAX_CRTCS", "num_crtc", "adev".
- Use findSpecificTypeInChildren only if needed to quickly obtain one child node, but a direct recursive traversal over children is recommended to find all ArraySubscriptExpr occurrences.

Step F: Heuristics and false positive control
- Only warn when both:
  - The loop condition contains “max_links” (preferably with “dc->caps”).
  - There is at least one array subscript in the body that:
    - Uses the same induction variable, and
    - Indexes a known per-CRTC array (crtcs/secure_display_ctxs) or a local pointer previously recognized as per-CRTC-sized via kcalloc/kmalloc_array with num_crtc/AMDGPU_MAX_CRTCS.
- Optionally require the presence of “adev” in both the condition and the base expression to ensure object relation.
- Do not attempt path-sensitive reasoning or symbolic bounds; keep the rule syntactic to stay simple and precise for this bug pattern.
