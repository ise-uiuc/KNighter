Plan

1) Program state
- No custom program states. We can detect this pattern reliably with an AST-only pass over function bodies and a lightweight interprocedural summary of “cleanup helpers” (functions that free specific members of their pointer parameters).

2) Callback selection
- Use checkASTCodeBody only.
  - First, summarize “cleanup helper” functions (callee-side) by inspecting their bodies and extracting which fields of which parameters they kfree.
  - Second, detect in a function body when there is a manual kfree of obj->field and, later in the same function, a call to a helper that (according to the summary) also frees the same field of the same object.

3) Helper data structures (checker-owned, not in ProgramState)
- A summary map for free-like side effects:
  - Map: const FunctionDecl* -> vector of (ParamIndex, const FieldDecl*)
  - Meaning: This function frees the given FieldDecl of the param at ParamIndex.
- No per-path maps needed; this is a source-order heuristic sufficient for destructor-like teardown patterns.

4) Utility helpers
- isKfreeLike(const CallEvent or CallExpr): returns true if callee is kfree/kvfree (can be extended to vfree if needed).
- extractFreedMemberFromArg(const Expr* Arg, const FieldDecl*& FD, const Expr*& BaseExpr):
  - If Arg is a MemberExpr whose member decl is a FieldDecl, set FD and BaseExpr to the MemberExpr’s base expression (ignoring parens/implicits), return true. Otherwise false.
- summarizeHelper(const FunctionDecl* FD):
  - If FD has a body, walk its body to find kfree-like calls.
  - For each such call, if the freed expression is a MemberExpr whose base originates from a function parameter (DeclRefExpr to ParamVarDecl), record (ParamIndex, FieldDecl*) in the summary map. Do not duplicate entries.
  - This can be called lazily on-demand when we first need the summary of a callee.
- sameObjectName(const Expr* A, const Expr* B, CheckerContext& C):
  - Heuristic equality: use ExprHasName on both sides’ top-level identifiers. For the caller side we match the base object “name” against the argument expression name for the helper call. This keeps the approach simple without alias tracking.

5) Summarization phase (inside checkASTCodeBody)
- For every FunctionDecl with a body that we visit, pre-summarize it as a potential helper using summarizeHelper(FD). This seeds summaries for callees we might use later.
- Also, implement lazy summarization: when we encounter a call to a callee that is not yet summarized but has a definition, call summarizeHelper on it on-demand.

6) Detection phase (inside checkASTCodeBody)
- For each FunctionDecl with body, perform a linear source-order scan of all CallExpr nodes in its body. You can implement this with a RecursiveASTVisitor that:
  - Collects all kfree-like calls encountered so far in this function into a vector of records: ManualFree { FieldDecl* FreedField, const Expr* BaseExpr, SourceLocation Loc }.
  - When visiting a kfree-like call:
    - If extractFreedMemberFromArg(Arg, FD, Base) returns true, push a new ManualFree record with FD and Base.
  - When visiting any CallExpr to a summarized helper H:
    - Obtain H’s summary entries: vector of (ParamIndex, FreedFieldFD).
    - For each summary entry:
      - Let ArgExpr = call’s actual argument at ParamIndex.
      - For each ManualFree recorded earlier in this function (only those with source location before the current call):
        - If ManualFree.FreedField == FreedFieldFD AND sameObjectName(ManualFree.BaseExpr, ArgExpr, C) is true, then report a double-free: the field was freed manually and will be freed again by the helper.
    - Note: This naturally handles the concrete pattern: kfree(ca->buckets_nouse); ...; bch2_dev_buckets_free(ca);
- Optional, catch the opposite order in the same function (helper first then manual free):
  - Maintain a HelperFreed list similar to ManualFree but populated when we see a helper call; then if a later kfree-like call frees the same field of the same base, report. This is symmetrical but not necessary for the provided patch; include it for robustness if desired.

7) Matching details
- Field identity: Compare FieldDecl* pointers (MemberExpr->getMemberDecl() dyn_cast<FieldDecl>).
- Object identity: Use the provided ExprHasName helper to check that the helper call’s actual argument contains the same base name as the manual free’s base expression. Prefer comparing DeclRefExpr of the base if available; fall back to ExprHasName for simplicity.

8) Reporting
- Create a single BugType for this checker (e.g., “Double free of struct member via helper”).
- When a match is found, emit a BasicBugReport:
  - Short message: “Double free of <field> via kfree() and <helper>()”.
  - Primary location: the manual kfree() call.
  - Add a note location at the helper call: “<helper>() also frees this field.”
- Use generateNonFatalErrorNode to ensure reporting does not stop analysis.

9) Scope and limitations
- This checker targets the common teardown pattern within a single function: manual free followed by a helper call that also frees the same member.
- It relies on intra-TU visibility of helper definitions to build summaries.
- It uses name-based matching for the object identity to keep the implementation simple and avoid ProgramState/alias tracking as suggested for minimizing steps.
