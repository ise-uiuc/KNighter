Plan

1) Program State
- REGISTER_TRAIT_WITH_PROGRAMSTATE(PendingAllocRegion, const MemRegion*)
  - Holds the lvalue region to which the most recent allocation return value was stored, waiting for the immediate NULL-check in the following branch condition.
- No alias map by default (keep it simple and reduce false positives to the immediate pattern).

2) Helper utilities
- isAllocator(const CallEvent &Call)
  - Return true if callee name matches one of: { "kzalloc", "kmalloc", "kcalloc", "kmalloc_array", "devm_kzalloc", "vmalloc", "kvzalloc", "kmemdup" }.
- getAssignedLHSRegionForCall(const CallEvent &Call, CheckerContext &C)
  - From Call.getOriginExpr(), go upward with findSpecificTypeInParents<BinaryOperator>(...) and:
    - If found an assignment BinaryOperator with opcode BO_Assign and the CallExpr is the RHS, return getMemRegionFromExpr(LHS, C).
  - If not found, try findSpecificTypeInParents<DeclStmt>(...) and:
    - Walk its VarDecls; if any has init equal to the CallExpr, return the MemRegion of that variable (use State->getLValue(VarDecl, LCtx) or getMemRegionFromExpr on a DeclRefExpr built from VarDecl as available).
  - If neither case works, return nullptr (skip).
- isNullCheck(const Expr *Cond, const Expr *&CheckedExpr, CheckerContext &C)
  - Recognize NULL checks:
    - UnaryOperator ‘!’: CheckedExpr = subexpr (IgnoreParenImpCasts).
    - BinaryOperator ‘==’ or ‘!=’: One side must be “null-like”:
      - IntegerLiteral 0, GNUNullExpr, CXXNullPtrLiteralExpr, or ExprHasName(side, "NULL", C).
      - The other side becomes CheckedExpr (IgnoreParenImpCasts).
    - A plain pointer in condition (if (ptr)): treat as non-null check. For this pattern we only care about explicit NULL checks (!ptr or ptr == NULL/0). Skip plain truthiness to avoid noise.
  - Return true only if we identified an explicit NULL check and extracted CheckedExpr.
- sameRegion(const MemRegion *A, const MemRegion *B)
  - Simple pointer comparison.

3) Callbacks and logic

A) checkPostCall(const CallEvent &Call, CheckerContext &C)
- Goal: Capture “allocate into X = alloc(...);” and remember X’s region for the very next NULL check.
- Steps:
  1. If not isAllocator(Call), return.
  2. Determine the assigned LHS region via getAssignedLHSRegionForCall(Call, C).
     - If no LHS region (e.g., return value not assigned), return; we only handle the explicit assignment/init pattern.
  3. State = C.getState(); State = State->set<PendingAllocRegion>(LHSRegion); C.addTransition(State).
- Rationale: We remember exactly which lvalue was assigned the allocation result; the next explicit NULL-check must be on this region.

B) checkBranchCondition(const Stmt *Condition, CheckerContext &C)
- Goal: On the immediate next branch after an allocation, verify the NULL check is on the same region. If it checks a different pointer, report a bug.
- Steps:
  1. Fetch State and PendingRegion = State->get<PendingAllocRegion>().
     - If PendingRegion is null, do nothing (return).
  2. Extract the conditional expression E = cast<Expr>(Condition).
  3. const Expr *CheckedExpr = nullptr; if (!isNullCheck(E->IgnoreParenImpCasts(), CheckedExpr, C)):
     - Not an explicit NULL check. To avoid stale pending state and false positives later, clear pending state and return.
  4. Obtain CheckedRegion = getMemRegionFromExpr(CheckedExpr, C).
     - If null (can’t map), clear pending state and return.
  5. Compare:
     - If sameRegion(CheckedRegion, PendingRegion):
       - Correct NULL check for the allocated pointer. Clear pending state (set<PendingAllocRegion>(nullptr)) and return.
     - Else:
       - Generate non-fatal error node and report:
         - Short message: "Mismatched NULL check after allocation"
         - Optional note: "Allocated pointer was not checked; a different pointer is checked here."
       - Clear pending state and add transition.
- Rationale: We constrain to the immediate, explicit NULL check after an allocation to minimize false positives, matching the kernel pattern in the patch.

C) checkBeginFunction(CheckerContext &C)
- Clear any stale state at function entry:
  - State = C.getState()->set<PendingAllocRegion>(nullptr); C.addTransition(State).

D) checkEndFunction(const ReturnStmt *RS, CheckerContext &C)
- Clear pending state to avoid state leakage across paths:
  - State = C.getState()->set<PendingAllocRegion>(nullptr); C.addTransition(State).

4) Reporting
- Create a BugType once (e.g., "Mismatched NULL check after allocation").
- In checkBranchCondition, upon mismatch:
  - Use generateNonFatalErrorNode to get ErrorNode.
  - Create a PathSensitiveBugReport with concise message: "Mismatched NULL check: checks a different pointer than the newly allocated one".
  - Optionally add a range on the branch condition and on the assignment LHS (if you still have access via parents; otherwise, at least the branch range).
  - Emit via C.emitReport.

5) Notes to reduce false positives
- Only trigger on explicit NULL checks (!ptr, ptr == NULL, ptr == 0), not on truthiness tests (if (ptr)).
- Only consider the first branch condition after the allocation call; clear state afterwards.
- Only handle cases where the allocation return value is assigned to a concrete lvalue (BinaryOperator assignment or VarDecl init). Ignore other patterns to keep the checker simple and precise.

6) Clang Check Functions used
- checkPostCall: capture allocator result assignment and store the destination region.
- checkBranchCondition: verify the immediate explicit NULL check refers to the same region; report mismatch.
- checkBeginFunction, checkEndFunction: cleanup/reset state.
