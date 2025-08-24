Plan

1) Program state and checker-owned caches
- Add a per-path set to remember which struct members of a specific base object have been freed in the current function:
  - REGISTER_SET_WITH_PROGRAMSTATE(FreedMemberSet, MemberKey)
  - MemberKey = { const MemRegion *BaseObj, const FieldDecl *Field } with a profile() method so it can be used in ProgramState. BaseObj is the MemRegion of the base pointer (e.g., the region for variable “ca”). Field is the FieldDecl of the freed member (e.g., buckets_nouse).
- Add a checker-internal summary cache (not in ProgramState) that records, for each cleanup function, which members of which parameter it frees:
  - DenseMap<const FunctionDecl*, SmallVector<FreedField, 4>> CalleeFreeSummary
  - FreedField = { unsigned ParamIndex; const FieldDecl *Field }
  - Key functions by their canonical decl to avoid duplicates.

2) Helper utilities (small static helpers inside the checker)
- bool isFreeLike(const CallEvent &Call):
  - Return true if callee name is one of: "kfree", "kvfree", "vfree" (keep minimal, at least "kfree" to hit the target).
- bool extractMemberOnParam(const Expr *E, const FunctionDecl *FD, unsigned &OutParamIdx, const FieldDecl *&OutFD):
  - E = E->IgnoreParenImpCasts(); expect MemberExpr ME (e.g., P->field or P.field).
  - From ME, take FieldDecl via ME->getMemberDecl()->getCanonicalDecl().
  - For ME->getBase()->IgnoreParenImpCasts():
    - If it is DeclRefExpr to ParmVarDecl of FD’s parameter list, set OutParamIdx to that parameter’s index.
    - Otherwise return false.
- bool extractBaseAndFieldFromMember(const Expr *E, CheckerContext &C, const MemRegion *&OutBaseRegion, const FieldDecl *&OutFD):
  - E = E->IgnoreParenImpCasts(); if not MemberExpr, return false.
  - OutFD = ME->getMemberDecl()->getCanonicalDecl().
  - Get base expression: Base = ME->getBase()->IgnoreParenImpCasts(); OutBaseRegion = getMemRegionFromExpr(Base, C). Return true if both available.
- MemberKey makeKey(const MemRegion *BaseRegion, const FieldDecl *FD):
  - Create a MemberKey from arguments; FD is canonical decl.
- const SmallVector<FreedField, 4> *getOrBuildSummary(const FunctionDecl *CalleeFD):
  - If CalleeFD not in CalleeFreeSummary and has body, scan once to build summary (see step 3).
  - Return pointer to summary vector (possibly empty) or nullptr if no body.

3) Build summaries of cleanup functions (who frees what) — checkASTCodeBody
- Implement checkASTCodeBody(const Decl *D, ...) to precompute summaries for all function bodies in the TU.
- For each FunctionDecl FD with a body:
  - Walk the function body (simple recursive walk or stack-based traversal) to locate CallExpr to free-like functions (kfree/kvfree/vfree).
  - For each free-like call, take its first argument A0. If extractMemberOnParam(A0, FD, ParamIdx, FieldDecl) is true, record FreedField{ParamIdx, FieldDecl} in CalleeFreeSummary[FD].
  - De-duplicate (e.g., by a small set keyed on (ParamIdx, FieldDecl)).
- This makes bch2_dev_buckets_free() summarized as “frees param0->buckets_nouse”.

4) Track direct frees and check for conflicts — checkPreCall
- Implement checkPreCall(const CallEvent &Call, CheckerContext &C):
  - Case A: Direct free in the current function
    - If isFreeLike(Call):
      - Get Arg0 = Call.getArgExpr(0); if extractBaseAndFieldFromMember(Arg0, C, BaseRegion, FD):
        - MemberKey K = makeKey(BaseRegion, FD).
        - If K already in FreedMemberSet: report bug (double free).
        - Else: add K to FreedMemberSet in ProgramState.
  - Case B: Calling a cleanup function that frees members of its parameter(s)
    - If const FunctionDecl *CalleeFD = dyn_cast_or_null<FunctionDecl>(Call.getDecl()):
      - const auto *Summary = getOrBuildSummary(CalleeFD).
      - If Summary is non-null:
        - For each FreedField {ParamIdx, FieldDecl} in *Summary:
          - If ParamIdx >= Call.getNumArgs(), continue.
          - Let Arg = Call.getArgExpr(ParamIdx).
          - Compute the base region of Arg: BaseRegion = getMemRegionFromExpr(Arg, C).
            - If BaseRegion is null, skip this entry.
          - MemberKey K = makeKey(BaseRegion, FieldDecl).
          - If K already in FreedMemberSet: report bug (double free due to earlier direct kfree or earlier cleanup that freed the same member).
          - Add K to FreedMemberSet (to prevent later duplicate frees after this call).

5) Optional: clear state per function — checkBeginFunction
- In checkBeginFunction, ensure the FreedMemberSet is empty at function entry (ProgramState starts clean by default; explicitly clearing is fine).

6) Reporting
- When detecting a double free, create a non-fatal error node and emit a PathSensitiveBugReport with a short message:
  - “Double free of member '<field_name>'”
- Attach the source range to the current call expression (the later free). If available, add an event note at the earlier free program point (optional).

7) Scope and simplifications
- This checker intentionally focuses on the most common, simple pattern:
  - Direct free arg is a MemberExpr (e.g., ca->buckets_nouse).
  - Cleanup frees direct members of its pointer parameter via kfree-like calls.
- It does not try to resolve aliasing (e.g., tmp = ca->buckets_nouse; kfree(tmp)), nested field chains beyond one level, or frees hidden behind additional helper layers (unless the helper itself is summarized).
- That simplicity is enough to detect the target bcachefs pattern: kfree(ca->buckets_nouse) followed by calling bch2_dev_buckets_free(ca), which frees ca->buckets_nouse again.

8) Utility functions usage
- getMemRegionFromExpr is used to obtain BaseRegion for MemberKey and for call arguments when composing cleanup frees.
- ExprHasName is not required but can help debugging or fallback checks when extracting fields.
- findSpecificTypeInChildren can be used in the AST walk in checkASTCodeBody to find CallExpr nodes, though a simple recursive traversal is sufficient.
