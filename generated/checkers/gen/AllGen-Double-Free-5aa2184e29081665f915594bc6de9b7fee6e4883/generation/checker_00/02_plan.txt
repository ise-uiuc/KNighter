Plan

1) Program state
- No custom program state is necessary. This checker will be purely AST-structural (function-body level) because the targeted pattern is a shared cleanup label that frees multiple resources, and at least one of them is a field of a function parameter that is not allocated/owned by the current function.

2) Callbacks
- Use only checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR).

3) Overall approach
- Within each function body:
  - Find cleanup labels and the frees they perform.
  - Find all gotos targeting those labels and the relative order of those gotos.
  - If a label frees a mix of resources (at least one locally allocated in this function and at least one member field of a parameter), and there are multiple error gotos to that label from different earlier points, report on the earlier goto(s): “Shared error label frees callee-owned field; potential double free. Split cleanups.”

4) Detailed steps for checkASTCodeBody

4.1) Pre-scan for local allocations
- Walk the function body (CompoundStmt) in source order.
- Collect names/Decls of variables that are locally allocated by the current function. A variable counts as “locally allocated” if:
  - It is assigned the result of kmalloc/kzalloc/kcalloc (standard kernel allocation family).
  - Implementation details:
    - For each BinaryOperator with op “=”, inspect the RHS; if it is a CallExpr whose callee name is one of {"kmalloc", "kzalloc", "kcalloc"}, record the LHS variable Decl as LocallyAllocated.
    - Also handle direct initialization of a variable with those calls (VarDecl with Init as CallExpr to kmalloc family).
  - This provides a conservative “OwnedByCaller” classification.

4.2) Collect cleanup labels and the resources they free
- Walk the body to find LabelStmt nodes; for each LabelStmt L:
  - Starting from the statement immediately following L, collect consecutive free calls until:
    - another LabelStmt is encountered, or
    - a ReturnStmt is encountered, or
    - the end of the compound statement.
  - A “free call” is any CallExpr whose callee name is in {"kfree", "kvfree", "vfree"}.
  - For each free call arg expression E (the pointer being freed), classify the freed resource:
    - IsParamMember(E): true if E is a MemberExpr and its base is a DeclRefExpr to a ParmVarDecl (e.g., mt->fc).
    - IsLocallyAllocated(E): true if E references a local variable that was captured in step 4.1.
      - If E is a DeclRefExpr of a local variable, check if that variable is in LocallyAllocated.
      - If E is a MemberExpr of a local aggregate variable, optionally check if we recorded that exact field; otherwise treat this as not LocallyAllocated (we only consider plain local pointer variables as “locally allocated” in this simple heuristic).
  - Store for label L:
    - The vector of freed expressions (keep the Expr*).
    - Two booleans: FreesAnyParamMember, FreesAnyLocallyAllocated.
    - Optionally, store a short string for each freed expression for diagnostics (use Lexer::getSourceText over E->getSourceRange()).

4.3) Collect gotos and map them to labels
- Walk the body and collect all GotoStmt nodes.
  - Record for each goto: its SourceLocation and its target LabelDecl (use GotoStmt::getLabel()).
  - For each GotoStmt, also try to find its enclosing IfStmt (the error check) using findSpecificTypeInParents<IfStmt>(GotoStmt, Ctx). This lets us confirm it’s in an if-branch used as an error path.
  - Keep a map LabelDecl* -> vector of GotoInfo {GotoStmt*, SourceLocation, EnclosingIfStmt*}.

4.4) Decide when to warn (suspicious shared cleanup)
- For each label L:
  - If L’s FreesAnyParamMember == true AND FreesAnyLocallyAllocated == true:
    - Retrieve the vector of gotos to L; sort them by SourceLocation using SourceManager::isBeforeInTranslationUnit().
    - If the vector size >= 2, that indicates “shared” error path (multiple error sites go to the same label).
    - For each goto except the last (i.e., earlier gotos in the function):
      - Optionally ensure it is in an error branch:
        - If EnclosingIfStmt is not null, and its condition looks like an error check (heuristic):
          - Accept any non-literal condition; or
          - Use ExprHasName on the IfStmt condition to check the presence of “ret” or a similarly named variable; either is fine; keep it simple.
      - Report a bug on that earlier GotoStmt:
        - Message: “Shared cleanup frees callee-owned pointer; potential double free. Split cleanups.”
        - If available, append the freed param member’s text, e.g., “(frees mt->fc)”.
        - Use BasicBugReport with a range at the goto token.
    - Rationale: A label that frees both a locally allocated buffer (owned by the current function) and a parameter’s member (likely managed by callees) is suspicious; if multiple different failure sites jump to this label, earlier sites may precede the point at which the param member became valid/owned and safe to free, causing an invalid/double free on those paths.

5) Utilities used
- ExprHasName to quickly check condition text for simple error checks (optional; not required for core logic).
- Lexer::getSourceText with the CheckerContext’s SourceManager/LangOptions (available in checkASTCodeBody via AnalysisManager) to extract readable names for freed expressions.
- findSpecificTypeInParents<IfStmt> to get the enclosing IfStmt for a GotoStmt, to ensure we focus on error-flow gotos.
- No need for EvaluateExprToInt, getArraySizeFromExpr, getStringSize, inferSymbolMaxVal, getMemRegionFromExpr in this checker.

6) Important filters to reduce false positives
- Only consider labels that free at least:
  - one ParamMember resource (e.g., mt->fc), AND
  - one LocallyAllocated resource (e.g., match_hl from kzalloc).
- Only warn on earlier gotos if there are at least two distinct gotos to the same label.
- Prefer reporting gotos that are inside an IfStmt branch (typical “if (ret) goto label;” pattern).

7) Bug report creation
- Use std::make_unique<BasicBugReport> because this is AST-level analysis in checkASTCodeBody.
- Short message as required: “Shared cleanup frees callee-owned pointer; potential double free. Split cleanups.”
- Highlight the goto statement and optionally add a note with the label name and the freed expression text.

8) Why this detects the target patch
- In the buggy code, the label free_fc freed both:
  - mt->fc (a param member likely not owned/created on the early-failure path), and
  - match_hl (a local kzalloc’d buffer).
- There were multiple gotos to free_fc from different failure sites. The earlier failure site (after the first helper) should not free mt->fc; our checker flags that early goto as jumping to a label that also frees the callee-owned pointer, suggesting to split into free_match_hl for that path.
