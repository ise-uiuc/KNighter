Plan

1) Program state and lightweight globals
- REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion*, unsigned)
  - Values: 0 = Unknown, 1 = LocalThisCPU (this_cpu_ptr-derived), 2 = RemoteCPU (per_cpu_ptr with explicit cpu arg not equal to smp_processor_id()).
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Track simple pointer aliases so classification propagates through assignments.
- Checker-level (non-state) containers:
  - mutable llvm::DenseSet<const Stmt*> Reported; // avoid duplicate reports per statement.
  - Optional: a BugType instance initialized once.

Rationale: We only need to know whether a pointer expression used as the base of a MemberExpr originates from this_cpu_ptr (local) or per_cpu_ptr with an explicit cpu (remote), and to propagate that classification via simple aliases. No heavier state is needed.

2) Helper utilities
- bool isCallNamed(const CallEvent/CallExpr*, StringRef)
  - Compare callee identifier name.
- bool isThisCpuPtrCall(const Expr* E)
  - Return true if E (ignoring casts/parens) is CallExpr and callee name is "this_cpu_ptr".
- bool isPerCpuPtrCall(const Expr* E)
  - Return true if callee name is "per_cpu_ptr".
- bool isLocalCPUExpr(const Expr* E)
  - Return true if E is a CallExpr named "smp_processor_id" or "raw_smp_processor_id". Otherwise false.
- unsigned classifyPerCpuCall(const CallExpr* CE)
  - If this_cpu_ptr: return LocalThisCPU.
  - If per_cpu_ptr: return isLocalCPUExpr(Arg1) ? LocalThisCPU : RemoteCPU.
  - Else 0.
- const MemRegion* baseRegionOfExpr(const Expr* E, CheckerContext &C)
  - getMemRegionFromExpr(E, C) and strip FieldElement/subregions back to the base variable region when needed.
- const MemRegion* resolveAlias(const MemRegion* R, ProgramStateRef St)
  - Follow PtrAliasMap chains to get the canonical mapped region.
- bool insideREADorWRITE_ONCE(const Expr* AnyChild, CheckerContext &C)
  - Find parent CallExpr (findSpecificTypeInParents<CallExpr>) and check if callee name is "READ_ONCE" or "WRITE_ONCE". Return true if yes.
- bool isZeroLiteral(const Expr* E, CheckerContext &C)
  - Use EvaluateExprToInt; return true if evaluation succeeded and result == 0.
- bool isRMWCompound(const CompoundAssignOperator* CAO)
  - Return true for +=, -=, ++, -- style ops (CompoundAssignOperator covers +=, -=; handle ++/-- via UnaryOperator below).

3) checkBeginFunction
- No state must persist per function; nothing required, but you may clear any lightweight function-local caches if you introduce them.

4) checkBind (pointer origin and alias tracking)
- Purpose: classify pointers as LocalThisCPU/RemoteCPU and propagate aliases.
- If S is a BinaryOperator that assigns to a DeclRefExpr pointer variable LHSVar and the RHS is:
  - A CallExpr CE to this_cpu_ptr/per_cpu_ptr:
    - Determine kind = classifyPerCpuCall(CE).
    - Get LHS region LReg via getMemRegionFromExpr on the LHS.
    - State = State->set<PerCpuPtrMap>(LReg, kind).
  - A DeclRefExpr or another pointer variable:
    - Resolve RHS region RReg (then resolveAlias via PtrAliasMap).
    - If PerCpuPtrMap has classification for RReg, set same classification for LReg.
    - Record alias: State = State->set<PtrAliasMap>(LReg, RReg).
  - A MemberExpr like “statc->parent”:
    - Get base region BReg of that MemberExpr (the “statc” variable) and resolve alias.
    - If PerCpuPtrMap has classification for BReg, set the same classification for LReg. This keeps “statc = statc->parent” classified as Local/Remote.
- Update C.addTransition(State) when changed.

5) checkPreStmt for BinaryOperator (writes/zeroing and RMW “x = x + val” if desired)
- Trigger on BinaryOperator with opcode BO_Assign.
- Extract LHS; if not a MemberExpr, ignore.
- Let ME = cast<MemberExpr>(LHS->IgnoreParenCasts()).
- Determine the base classification:
  - Case A: base expression of ME is a CallExpr to this_cpu_ptr/per_cpu_ptr => classifyPerCpuCall.
  - Case B: base is a DeclRefExpr (e.g., “statc”):
    - Get base region, resolve alias, and look up PerCpuPtrMap classification.
  - If classification is 0 (unknown), ignore.
- If insideREADorWRITE_ONCE(LHS, C) is true, ignore (already protected).
- Now decide if to warn:
  - If classification == RemoteCPU:
    - Any write to a per-CPU field should use WRITE_ONCE. If not, report.
    - This covers “statc->stats_updates = 0” in the flush path.
  - If classification == LocalThisCPU:
    - This assignment might be an RMW disguised as “x = x + k”. If you want to be precise, check RHS subtree for a MemberExpr equivalent to LHS (same FieldDecl and same base variable after alias resolution). If detected and no READ/WRITE_ONCE protecting, report.
    - Simpler (acceptable): only warn for Local RMW in CompoundAssignOperator/UnaryOperator and do not warn for plain “=”. See next steps.

6) checkPreStmt for CompoundAssignOperator (local RMW like “+=”, “-=”
- Trigger on CompoundAssignOperator.
- If LHS is not MemberExpr, ignore.
- Compute base classification as in step 5.
- If classification == LocalThisCPU and not inside READ/WRITE_ONCE (on the LHS), report:
  - Message: “RMW on per-CPU field without READ_ONCE/WRITE_ONCE; field may be accessed from other CPUs.”
- If classification == RemoteCPU and not inside WRITE_ONCE, also report (rare but still unsafe).

7) checkPreStmt for UnaryOperator (++/--)
- Trigger on UnaryOperator with opcode UO_PreInc, UO_PostInc, UO_PreDec, UO_PostDec.
- If operand is a MemberExpr, classify base as in step 5.
- If LocalThisCPU and not inside READ/WRITE_ONCE, report same as step 6.
- If RemoteCPU and not inside WRITE_ONCE, report.

8) Macro-protected patterns (avoid FPs)
- Skip reporting if the MemberExpr is an argument to a WRITE_ONCE/READ_ONCE call:
  - For remote writes (assignments), require WRITE_ONCE.
  - For local RMW, require both READ_ONCE and WRITE_ONCE pattern; practically, the presence of either READ_ONCE on the read side or WRITE_ONCE on the write side will change the AST shape and avoid a raw CompoundAssignOperator. In our checker we simply skip if insideREADorWRITE_ONCE is true.

9) Bug report
- When a violation is detected, create a non-fatal error node with C.generateNonFatalErrorNode().
- Emit a PathSensitiveBugReport with a short message:
  - For remote write: “Remote per-CPU field write without WRITE_ONCE.”
  - For local RMW: “RMW on per-CPU field without READ_ONCE/WRITE_ONCE.”
- Use the assignment/compound/unary operator statement as the location. Gate with the Reported set to avoid duplicates for the same Stmt.

10) Notes on coverage and simplicity
- This plan intentionally focuses on:
  - Detecting writes to per-CPU fields through this_cpu_ptr/per_cpu_ptr-derived pointers.
  - Flagging remote writes lacking WRITE_ONCE.
  - Flagging local RMW operations (+=, ++, etc.) lacking READ/WRITE_ONCE.
- It does not require whole-program knowledge of other functions: the remote path is directly recognized by per_cpu_ptr’s cpu argument, and local RMW is recognized by CompoundAssign/Unary ops.
- Aliasing within the function is handled via PtrAliasMap. Assignments like “statc = statc->parent” retain classification.

11) Callback summary
- checkBeginFunction: optional cleanup.
- checkBind: classify pointer variables as LocalThisCPU/RemoteCPU; propagate via PtrAliasMap; keep classification through “->parent” assignments.
- checkPreStmt(CompoundAssignOperator): detect local RMW on per-CPU field without READ/WRITE_ONCE; report.
- checkPreStmt(UnaryOperator ++/--): same as above.
- checkPreStmt(BinaryOperator BO_Assign): detect remote write to per-CPU field without WRITE_ONCE; optionally detect “x = x + k” RMW if you implement LHS-in-RHS check; report.

This is the simplest, targeted approach to catch the kernel bug pattern: plain read-modify-write or zeroing of per-CPU fields used cross-CPU, without READ_ONCE/WRITE_ONCE.
