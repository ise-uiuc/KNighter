Plan

1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(StructInitRiskMap, const VarDecl *, bool)
  - Key: the VarDecl of a stack-allocated struct.
  - Value: true = may contain uninitialized bytes (risky); false = known zeroed (safe).
- Rationale: We only need to know “risky vs. safe” per local struct. We match later via VarDecl extracted from the MemRegion of “&var”.

2. Helpers
- isLocalRecordVar(const VarDecl *VD):
  - return VD && VD->isLocalVarDecl() && VD->hasLocalStorage() && VD->getType()->isRecordType() && !VD->isStaticLocal();
- getVarDeclFromArg(const Expr *E, CheckerContext &C):
  - Use getMemRegionFromExpr(E, C).
  - If region exists, take R->getBaseRegion(), dyn_cast<VarRegion>, then return cast<VarDecl>(VR->getDecl()).
- isSizeofVar(const Expr *LenExpr, const VarDecl *VD):
  - Using findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(LenExpr) find a UETT_SizeOf.
  - If the sizeof refers to an expression: check if it’s a DeclRefExpr of the same VD.
  - If the sizeof refers to a type: compare it with VD->getType() (ignoring qualifiers). If they are the same record type, return true.
- isZeroInt(const Expr *E, CheckerContext &C):
  - Use EvaluateExprToInt; if true and value == 0, return true.
- isMemsetZeroWholeVar(const CallEvent &Call, const VarDecl *VD, CheckerContext &C):
  - Callee name must be “memset” or “__builtin_memset”.
  - Arg0: buffer, Arg1: value, Arg2: size.
  - Arg1 must be zero via isZeroInt.
  - Arg0 must be &VD (use getVarDeclFromArg on Arg0 and compare to VD).
  - Arg2 must be sizeof(VD) via isSizeofVar(Arg2, VD).
- getExportToUserLayout(const CallEvent &Call, unsigned &LenIdx, unsigned &DataIdx):
  - For the following names, set indices and return true:
    - “nla_put”: LenIdx=2, DataIdx=3
    - “nla_put_64bit”: LenIdx=2, DataIdx=3
    - “nla_put_nohdr”: LenIdx=0, DataIdx=1
    - “copy_to_user”: LenIdx=2, DataIdx=1
    - “copy_to_user_iter”: LenIdx=2, DataIdx=1
  - Otherwise return false.

3. checkPostStmt(const DeclStmt *DS)
- For each decl in DS:
  - If VarDecl* VD and isLocalRecordVar(VD):
    - If no initializer: mark risky: State = State->set<StructInitRiskMap>(VD, true).
    - If has initializer:
      - If it is an InitListExpr:
        - If getNumInits() == 0 (i.e., “{}”): consider safe: State->set(VD, false).
        - Otherwise, consider risky: State->set(VD, true).
      - Else: conservatively mark risky (true).
    - Note: We intentionally do not attempt field-level tracking; this keeps the checker simple and aligns with the kernel’s guidance to use memset for padding.

4. checkPostCall(const CallEvent &Call, CheckerContext &C)
- Detect memset zeroing that clears the entire struct:
  - For each entry (VD -> bool) in StructInitRiskMap where value is true:
    - If isMemsetZeroWholeVar(Call, VD, C) is true:
      - Set VD to safe: State->set<StructInitRiskMap>(VD, false).
- No other modeling needed.

5. checkPreCall(const CallEvent &Call, CheckerContext &C)
- Identify export-to-user functions:
  - unsigned LenIdx, DataIdx; if !getExportToUserLayout(Call, LenIdx, DataIdx) return.
- Extract the data VarDecl:
  - const Expr *DataE = Call.getArgExpr(DataIdx);
  - const VarDecl *VD = getVarDeclFromArg(DataE, C).
  - Require VD != nullptr and isLocalRecordVar(VD).
  - Additionally, ensure the data expression is the address of the whole object (not a field):
    - If the MemRegion from DataE base is a VarRegion (not FieldRegion/ElementRegion), accept; otherwise skip (we only warn on copying the whole struct object).
- Ensure the length matches sizeof(var):
  - const Expr *LenE = Call.getArgExpr(LenIdx);
  - If !isSizeofVar(LenE, VD), return (only warn on whole-struct copies).
- Consult map:
  - bool Risky; if State->lookup<StructInitRiskMap>(VD, Risky) && Risky == true:
    - Report a bug.

6. Bug reporting
- Use generateNonFatalErrorNode() and std::make_unique<PathSensitiveBugReport>.
- BugType: “Kernel infoleak: partial struct init”.
- Message: “Partially initialized stack struct copied to user; zero it with memset.”
- Add ranges:
  - Highlight DataE and LenE ranges if available.

7. Notes and simplifications
- We only clear risk via an explicit memset(&var, 0, sizeof(var)). Other patterns (e.g., s = (struct S){0};) are not considered; this avoids complex modeling and matches kernel guidance.
- We only warn when:
  - The data pointer is the address of a stack struct object (not a field),
  - The length is sizeof(the struct object or its type),
  - The variable is marked risky at that point.
- This is intentionally conservative and simple; it will catch the target pattern demonstrated in the provided patch (designated/partial initializer + nla_put with sizeof(var)).
