Plan

1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion*, bool)
  - Tracks regions that are “per-CPU pointers” (true if returned from this_cpu_ptr/per_cpu_ptr/raw_cpu_ptr or aliased from them).
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks pointer-to-pointer aliases so we can propagate the “per-CPU pointer” property.

2. Helper predicates and utilities
- isPerCpuPtrCallee(const CallEvent&): return true if callee name is one of:
  - "this_cpu_ptr", "per_cpu_ptr", "raw_cpu_ptr"
- isCompoundAssign(const BinaryOperator* BO): return true for BO_AddAssign, BO_SubAssign, BO_MulAssign, BO_DivAssign, BO_RemAssign, BO_AndAssign, BO_OrAssign, BO_XorAssign, BO_ShlAssign, BO_ShrAssign.
- isIncDec(const UnaryOperator* UO): return true for UO_PreInc, UO_PreDec, UO_PostInc, UO_PostDec.
- getRootAlias(const MemRegion* R, ProgramStateRef State): follow PtrAliasMap to the root aliased region if exists; else return R.
- isPerCpuBaseRegion(const MemRegion* R, ProgramStateRef State): check PerCpuPtrMap[R] == true, or if R is aliased to a region with PerCpuPtrMap true.
- getMemberBaseRegion(const MemberExpr* ME, CheckerContext& C): return the MemRegion* for ME->getBase() via getMemRegionFromExpr.
- sameFieldRegion(const Expr* A, const Expr* B, CheckerContext& C): resolve regions for A and B via getMemRegionFromExpr and compare pointer equality (use when both are MemberExpr).
- protectedByREAD_ONCE(const Expr* E, CheckerContext& C): return ExprHasName(E, "READ_ONCE(", C).
- protectedByWRITE_ONCE(const Expr* E, CheckerContext& C): return ExprHasName(E, "WRITE_ONCE(", C).

3. checkPostCall (mark per-CPU pointers)
- When isPerCpuPtrCallee(Call) is true:
  - Obtain the return expression from Call.getOriginExpr().
  - Get its region Rret: getMemRegionFromExpr(Call.getOriginExpr(), C).
  - If Rret != nullptr, set PerCpuPtrMap[Rret] = true in the state.

4. checkBind (propagate aliasing; detect racy updates)
- Pointer aliasing
  - If Val is a loc::MemRegionVal or is a pointer SVal with a MemRegion Rsrc and Loc is a MemRegion Rdst representing a pointer-typed storage (VarRegion, FieldRegion of pointer type):
    - Let Root = getRootAlias(Rsrc, State).
    - If PerCpuPtrMap[Root] == true, then set PtrAliasMap[Rdst] = Root and optionally PerCpuPtrMap[Rdst] = true to ease future queries.

- Detect racy per-CPU field updates
  - Determine if S is a BinaryOperator (BO) or a UnaryOperator (UO). If not, return.
    - For compound assignment (isCompoundAssign(BO)):
      - Let LHS = dyn_cast<MemberExpr>(BO->getLHS()->IgnoreParenCasts()).
      - If !LHS, return.
      - BaseR = getMemberBaseRegion(LHS, C). If !BaseR, return.
      - If !isPerCpuBaseRegion(BaseR, State), return.
      - If protectedByREAD_ONCE(BO, C) or protectedByWRITE_ONCE(BO, C), return (best-effort macro guard).
      - Report: “Non-atomic update to per-CPU field; use READ_ONCE/WRITE_ONCE.”
    - For inc/dec (isIncDec(UO)):
      - Let SubE = dyn_cast<MemberExpr>(UO->getSubExpr()->IgnoreParenCasts()).
      - If !SubE, return.
      - BaseR = getMemberBaseRegion(SubE, C). If !BaseR, return.
      - If !isPerCpuBaseRegion(BaseR, State), return.
      - If protectedByREAD_ONCE(UO, C) or protectedByWRITE_ONCE(UO, C), return.
      - Report as above.
    - For plain assignment (BO->getOpcode() == BO_Assign):
      - Let LHS_ME = dyn_cast<MemberExpr>(BO->getLHS()->IgnoreParenCasts()).
      - If !LHS_ME, return.
      - BaseR = getMemberBaseRegion(LHS_ME, C). If !BaseR, return.
      - If !isPerCpuBaseRegion(BaseR, State), return.
      - If protectedByWRITE_ONCE(BO, C), return.
      - Check two sub-patterns:
        1) RMW via self-reference on RHS:
           - Try to locate a MemberExpr on RHS: const MemberExpr* RHS_ME = findSpecificTypeInChildren<MemberExpr>(BO->getRHS()).
           - If RHS_ME && sameFieldRegion(LHS_ME, RHS_ME, C) and not protectedByREAD_ONCE(BO->getRHS(), C):
             - Report: “Plain read/modify/write of per-CPU field; use READ_ONCE/WRITE_ONCE.”
        2) Clear to zero:
           - Attempt to EvaluateExprToInt(RHS_val, BO->getRHS(), C). If success and RHS_val == 0:
             - Report: “Clearing per-CPU field without WRITE_ONCE; use WRITE_ONCE(field, 0).”

- Reporting
  - Use a single BugType, e.g., “Racy per-CPU field update”.
  - Create a non-fatal error node and emit a PathSensitiveBugReport with a short message:
    - For compound/inc/dec: “Non-atomic update to per-CPU field; use READ_ONCE/WRITE_ONCE.”
    - For RMW: “Plain read/modify/write of per-CPU field; use READ_ONCE/WRITE_ONCE.”
    - For zeroing: “Clearing per-CPU field without WRITE_ONCE.”

5. Optional: tighten matches to integer fields
- Before reporting, check that the LHS MemberExpr type is an integer or enum of size <= 8 bytes to focus on fields susceptible to torn accesses:
  - QualType T = LHS_ME->getType(); if !T->isIntegerType() return; Use ASTContext.getTypeSizeInChars(T) to gate if desired.

6. Notes on using provided utilities
- getMemRegionFromExpr is used to resolve regions for return values, member bases, and alias sources/destinations.
- findSpecificTypeInChildren<MemberExpr> helps to find self-referential RMW on RHS.
- ExprHasName is used to detect macro protection (READ_ONCE/WRITE_ONCE) based on source text.
- EvaluateExprToInt detects “= 0” zeroing assignments to trigger the WRITE_ONCE diagnostic.

7. Callbacks used summary
- checkPostCall:
  - Mark return regions of this_cpu_ptr/per_cpu_ptr/raw_cpu_ptr as per-CPU pointers.
- checkBind:
  - Propagate pointer aliasing for per-CPU pointers.
  - Detect and report non-atomic compound assignments, inc/dec, RMW, and zeroing assignments on fields reached through per-CPU pointers.

This minimal stateful tracking plus syntax-pattern checks captures the target bug: plain RMW or clear on a per-CPU field that can be accessed from other CPUs, and suggests the correct use of READ_ONCE/WRITE_ONCE.
