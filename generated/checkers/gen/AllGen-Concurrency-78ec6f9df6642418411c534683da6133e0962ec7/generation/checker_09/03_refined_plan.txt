Plan

1) Program state
- No custom program state is required. This checker is an AST-level, cross-function pattern detector. We only need checker-internal containers to accumulate evidence across all functions in the TU and then report once we know both sides of the pattern exist.

2) Data kept in the checker (member fields)
- RemotePlainFieldSet: set of field keys that are accessed through per_cpu_ptr(..., cpu) without READ_ONCE/WRITE_ONCE.
  - Each key is a pair: (PointeeRecordTypeName, FieldName).
- LocalRMWHazards: vector of hazard records collected at this_cpu_ptr sites:
  - Each hazard record stores:
    - FieldKey (PointeeRecordTypeName, FieldName)
    - const MemberExpr* ME (for location/range)
    - A short message string for the report
- A BugType instance: “Per-CPU data race”.

3) Helper utilities to implement inside the checker
- getRecordTypeName(QualType QT): return qualified name of the pointee record type; if QT is T*, get record name of T (use QT->getPointeeType()->getAsRecordDecl()).
- makeFieldKey(const VarDecl *BaseVar, const MemberExpr *ME):
  - Get pointee record type name from BaseVar->getType().
  - Get field name from ME->getMemberDecl()->getNameAsString().
- isCallNamed(const Expr *E, StringRef Name, CheckerContext &C):
  - Use ExprHasName(E, Name, C) to check source text contains the macro/function name.
- isPerCpuPtrCall(const Expr *E, unsigned &NumArgs, CheckerContext &C):
  - If E->IgnoreImplicit() is CallExpr and ExprHasName(E, "per_cpu_ptr", C) is true, set NumArgs = CE->getNumArgs(), return true.
- isThisCpuPtrCall(const Expr *E, CheckerContext &C):
  - If E->IgnoreImplicit() is CallExpr and ExprHasName(E, "this_cpu_ptr", C) is true, return true.
- isReadOrWriteOnceContext(const Expr *E, CheckerContext &C):
  - Walk up parents from E using findSpecificTypeInParents<CallExpr>. If found, and callee text contains "READ_ONCE" or "WRITE_ONCE" via ExprHasName, return true. Else false.
- getBaseVar(const Expr *Base):
  - If Base->IgnoreParenImpCasts() is DeclRefExpr, return its VarDecl*. If it’s a UnaryOperator (deref) of DeclRefExpr, unwrap and return the VarDecl*. If it’s an implicit temporary, return nullptr.
- isRMWOnMember(const MemberExpr *ME, CheckerContext &C):
  - Check parents:
    - If parent is CompoundAssignOperator (+=, -=, |=, &=, ^=, <<=, >>=), and its LHS contains ME (compare pointer after IgnoreParenImpCasts), return true.
    - If parent is UnaryOperator (pre/post ++/--), return true.
  - Otherwise false.

4) Per-function local analysis (inside checkASTCodeBody)
We will scan each function body once, building a local map of variables that originate from per_cpu_ptr or this_cpu_ptr. Then we will inspect all member accesses through those variables to classify accesses and collect hazards. Note: no path-sensitivity is needed.

Data (function-scoped):
- VarKindMap: map<const VarDecl*, enum { Unknown, RemoteCPU, ThisCPU }>

Steps:
- Build VarKindMap by scanning:
  - Variable definitions with initializers: for each DeclStmt:
    - For each VarDecl with an initializer RHS:
      - If RHS is a CallExpr and isPerCpuPtrCall(RHS, NumArgs, C) is true and NumArgs >= 2, set VarKindMap[VD] = RemoteCPU.
      - Else if RHS is a CallExpr and isThisCpuPtrCall(RHS, C), set VarKindMap[VD] = ThisCPU.
  - Simple assignments: scan BinaryOperator “=”:
    - If LHS is a DeclRefExpr to VarDecl* V, and RHS is a CallExpr:
      - If per_cpu_ptr(...) with 2 args => VarKindMap[V] = RemoteCPU.
      - If this_cpu_ptr(...) => VarKindMap[V] = ThisCPU.
- Also handle direct use without a temp:
  - When we later visit a MemberExpr, if its base is directly a CallExpr to per_cpu_ptr or this_cpu_ptr, we treat it as RemoteCPU or ThisCPU respectively even if no VarDecl was recorded.
- MemberExpr inspection:
  - For every MemberExpr in the function body:
    - Determine the base “source”:
      - First, try to retrieve a VarDecl via getBaseVar(ME->getBase()).
      - If no VarDecl, check if base is a CallExpr:
        - If per_cpu_ptr(..., 2 args) => treat as RemoteCPU.
        - If this_cpu_ptr(...) => treat as ThisCPU.
      - Otherwise skip.
    - Determine whether the access is within READ_ONCE/WRITE_ONCE using isReadOrWriteOnceContext(ME, C). If true, skip (safe).
    - Build FieldKey via makeFieldKey(BaseVarOrSynthetic, ME). For the synthetic case (base is a CallExpr), use the pointee type of the CallExpr’s type.
    - Classify the access:
      - RemoteCPU member access (not READ/WRITE_ONCE): record RemotePlainFieldSet.insert(FieldKey).
      - ThisCPU member access: if isRMWOnMember(ME, C) is true (and not READ/WRITE_ONCE), record hazard: LocalRMWHazards.emplace_back(ME, FieldKey, "Non-atomic RMW on per-CPU field also accessed cross-CPU").
    - Ignore ThisCPU plain read/write that are not RMW, to keep the checker focused on the target pattern and reduce false positives.
- Note: We do not attempt alias analysis across variables; a variable becomes RemoteCPU or ThisCPU only when directly assigned from a matching call. This is sufficient to detect the target pattern in the provided patch and typical kernel code.

5) Final reporting after full TU is analyzed (checkEndAnalysis)
- Iterate over LocalRMWHazards:
  - If the hazard’s FieldKey exists in RemotePlainFieldSet, emit a report.
    - Use BasicBugReport with the checker’s BugType.
    - Message: “Racy per-CPU field: non-atomic RMW and cross-CPU plain access.”
    - Location/Range: ME->getSourceRange().
- Rationale: Warning only when both sides are present in the same translation unit minimizes noise:
  - this_cpu_ptr RMW is flagged only if there is also a plain remote per_cpu_ptr access to the same field elsewhere.
  - We require that the remote access is not guarded by READ_ONCE/WRITE_ONCE, matching the fix.

6) Callback selection and how to implement them
- checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const
  - If D has a body, traverse it:
    - Implement a small recursive walker (e.g., RecursiveASTVisitor inside the checker) to visit DeclStmt, BinaryOperator (=), CallExpr, MemberExpr, UnaryOperator, CompoundAssignOperator.
    - Fill VarKindMap by looking at initializers and assignment RHS as described.
    - For each MemberExpr, classify as RemoteCPU or ThisCPU (including direct call bases), check for READ_ONCE/WRITE_ONCE with isReadOrWriteOnceContext, and record into RemotePlainFieldSet or LocalRMWHazards accordingly.
  - Do not emit any reports here.
- checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const
  - For each hazard in LocalRMWHazards, if its FieldKey is in RemotePlainFieldSet, create and emit a BasicBugReport tied to the MemberExpr’s location.
  - Keep the message short.

7) Heuristics and filters to reduce false positives
- Only treat per_cpu_ptr as “remote” when it has 2 or more arguments (per_cpu_ptr(ptr, cpu)).
- Treat this_cpu_ptr as “local” on the current CPU (one argument).
- Exempt member accesses wrapped in READ_ONCE/WRITE_ONCE. Use ExprHasName on the parent CallExpr to detect these macros reliably in macro-expanded code.
- Only flag this_cpu_ptr operations when they are RMW (CompoundAssignOperator or ++/--) to closely align with the bug pattern.
- FieldKey requires both pointee record type name and field name to match (e.g., “memcg_vmstats_percpu::stats_updates”), ensuring we report only when the exact field matches on both sides.

8) Where to use provided Utility Functions
- ExprHasName: to detect macro/function names in source for per_cpu_ptr, this_cpu_ptr, READ_ONCE, WRITE_ONCE.
- findSpecificTypeInParents: to find the enclosing CallExpr for detecting READ_ONCE/WRITE_ONCE, and to find enclosing CompoundAssignOperator or UnaryOperator during RMW detection.
- findSpecificTypeInChildren: not necessary for this checker.
- The other utilities (EvaluateExprToInt, getMemRegionFromExpr, etc.) are not needed for this pattern.

9) Report message
- Keep it short and clear:
  - Title: “Per-CPU data race”
  - Message: “Racy per-CPU field: non-atomic RMW and cross-CPU plain access.”
  - Point to the this_cpu_ptr RMW MemberExpr location.
