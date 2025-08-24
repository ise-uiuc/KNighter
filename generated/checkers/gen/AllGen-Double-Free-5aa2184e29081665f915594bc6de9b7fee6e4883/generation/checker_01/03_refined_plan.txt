Plan

1. Program state
- No custom program state is necessary. We will implement this checker as a single AST-body pass that matches a specific error-cleanup-with-goto anti-pattern.

2. Callbacks
- Use only checkASTCodeBody. We will:
  - Walk the function body to collect:
    - All label-based cleanup regions and the free() operations in them.
    - All if-statements that perform a goto-based early-exit after a failing call.
  - Correlate these two to warn if the early-exit path frees a member field of a struct argument that the current function did not initialize before the failing call (likely callee-owned), which indicates possible double-free or invalid free.

3. Implementation steps in checkASTCodeBody

Step A: Prepare helpers and constants
- Known free functions: maintain a small set: {"kfree", "kvfree", "vfree"}.
- Helper: isKnownFreeCall(const CallExpr* CE)
  - Get callee IdentifierInfo; return true if in known set.
- Helper: getFreedExpr(const CallExpr* CE)
  - Return CE->getArg(0)->IgnoreImpCasts().
- Helper: isMemberOfVar(const Expr* E, const VarDecl* V, std::string* FieldNameOut)
  - If E is a MemberExpr (E->IgnoreImpCasts()), base is a DeclRefExpr to VarDecl == V, return true and optionally store the field name.
- Helper: findEnclosingCompound(const Stmt* S, CheckerContext &C)
  - Use findSpecificTypeInParents<CompoundStmt>(S, C) to get nearest enclosing compound block.
- Helper: getIndexInCompound(const CompoundStmt* CS, const Stmt* S)
  - Walk CS->body(); find index of S.
- Helper: findFirstGotoInThen(const IfStmt* IfS)
  - If Then is a GotoStmt, return it; if Then is a CompoundStmt, linearly scan children and return the first GotoStmt found; otherwise nullptr.
- Helper: getTargetLabelName(const GotoStmt* GS)
  - GS->getLabel()->getName().
- Helper: findCallBeforeIf(const IfStmt* IfS, CheckerContext &C)
  - Strategy (in order):
    - If IfS->getCond() is a CallExpr, return it (failing call is in condition).
    - Else, find enclosing CompoundStmt CS and the previous sibling statement Prev before IfS:
      - If Prev is a BinaryOperator assignment and RHS is CallExpr, return that CallExpr.
      - If Prev is a DeclStmt with one declarator initialized by a CallExpr, return that CallExpr.
    - Else nullptr.
- Helper: collectStructPtrArgs(const CallExpr* CE, SmallVector<const VarDecl*, 4>& Out)
  - For each CE arg: if it’s a DeclRefExpr whose type is a pointer to a RecordType (struct/union), collect its VarDecl.
- Helper: stmtContainsAssignmentToMember(const Stmt* S, const VarDecl* Base, StringRef Field)
  - Return true if within S there exists a BinaryOperator assignment where LHS is a MemberExpr with base DeclRefExpr to Base and member name matches Field.

Step B: Build label-to-cleanup map
- Iterate the function body to record cleanup regions:
  - For every LabelStmt L:
    - Find its enclosing CompoundStmt CS and the index Idx of L in CS.
    - Walk forward in CS from Idx:
      - For the current statement St:
        - If it is another LabelStmt and not the first statement (i.e., Idx2 > Idx), stop (cleanup region ends).
        - If it is a ReturnStmt, BreakStmt, or GotoStmt (a control terminator), include it if at Idx (LabelStmt’s own child), then stop after processing current.
        - For each statement in this linear region, try to find a CallExpr using findSpecificTypeInChildren<CallExpr>(St).
          - If it is a known free call, record a FreedTarget:
            - Fields: LabelName, FreeCallStmt (for report range), CalleeName, FreedExpr (argument 0, ignoring casts).
      - Continue to next statement until one of the above stopping conditions or end of CS.
  - Maintain a map LabelName -> vector<FreedTarget> CleanupMap.

Step C: Detect early-error goto after failing call
- Walk all IfStmt nodes:
  - Obtain the first then-branch GotoStmt GS = findFirstGotoInThen(IfS); if none, continue.
  - Identify the failing call CE = findCallBeforeIf(IfS, C); if none, continue.
  - Collect struct pointer arguments of CE into StructArgs (VarDecl pointers).
  - If StructArgs is empty, continue.
  - Get target label name L = getTargetLabelName(GS); look up CleanupMap[L]. If none, continue.

Step D: Determine suspicious frees in the label’s cleanup region
- For each FreedTarget FT in CleanupMap[L]:
  - If FT.FreedExpr is a MemberExpr ME and its base is a DeclRefExpr whose VarDecl is one of StructArgs (call’s struct pointer parameters), then we suspect that we are freeing callee-owned (or not-initialized-by-this-function) memory on the early error path.
  - To reduce false positives, check if this field was assigned within this function before the IfStmt:
    - Let ME’s member field name be FieldName.
    - Find enclosing CompoundStmt CS of IfS and its index IdxIf.
    - For all sibling statements in CS with index < IdxIf:
      - If stmtContainsAssignmentToMember(S, BaseVarDecl, FieldName) returns true for any, then consider this free as locally-initialized (skip warning for this FT).
  - If no prior local assignment found, emit a warning.

Step E: Bug reporting
- For each suspicious FT (no prior assignment), create a BasicBugReport:
  - Short message: "Suspicious free of 'param->field' in early error path; may double free or free uninitialized memory"
  - Primary location/range: the free call site (FT.FreeCallStmt).
  - Optionally, add a note with the failing call location (CE) to aid understanding.
- Only one report per FT.

4. Notes and simplifications
- This checker is intentionally heuristic and scoped:
  - It flags when the early-error goto after a failing call leads to a cleanup region that frees a member of a struct pointer argument to that failing call, but the member was never assigned in the current function prior to the IfStmt. This mirrors the target bug where mt->fc is freed in the early error path even though it is managed by the callee hws_definer_conv_match_params_to_hl().
  - It handles common C kernel patterns:
    - if (ret) goto out;
    - if (func(...)) goto out;
    - Label-based cleanup with linear sequence of kfree() calls.
- Utility usage:
  - Use findSpecificTypeInParents<CompoundStmt> to locate enclosing blocks.
  - Use findSpecificTypeInChildren<CallExpr>/BinaryOperator to search inside statements.
  - Use ExprHasName for simple name checks when matching member fields if desired, though MemberExpr inspection is preferred.
- No interprocedural modeling or taint/state tracking is required for this pattern.
