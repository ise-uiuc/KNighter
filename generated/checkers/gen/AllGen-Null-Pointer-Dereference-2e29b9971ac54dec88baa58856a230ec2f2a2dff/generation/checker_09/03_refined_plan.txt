1) Program state

- Use a single optional trait to remember the most recent “allocated target” that is expected to be NULL-checked immediately.
  - REGISTER_TRAIT_WITH_PROGRAMSTATE(LastAllocRegion, const MemRegion*)
    - When non-null, it means “the last call to an allocator assigned to this region, and we expect the very next if-condition to NULL-check this region.”
  - No alias map or counters are needed for this checker to keep it simple and focused on the immediate-mismatch pattern.

2) Callbacks and how to implement

A) checkPostCall — capture “allocation assigned to a field/ptr” and arm the checker
- Goal: Detect calls to allocators and identify the LHS the return value is assigned to.
- Steps:
  1. Recognize allocator functions:
     - Create a helper isAllocator(const CallEvent&): match common kernel allocators that can return NULL:
       - kzalloc, kmalloc, kcalloc, kvzalloc, kvmalloc, kvmalloc_array, kmalloc_array, devm_kzalloc (optional).
     - Return true if the callee name matches one of these.
  2. If isAllocator(Call) is false, return.
  3. Find the LHS of the call’s enclosing assignment/initializer:
     - Use findSpecificTypeInParents<BinaryOperator>(Call.getOriginExpr(), C) and check opcode is BO_Assign. If found, LHS = BO->getLHS().
     - If not found, try findSpecificTypeInParents<DeclStmt>, fetch the VarDecl being initialized by this call (handle single-declarator DeclStmt), LHS = DeclRefExpr of that VarDecl.
     - If we cannot obtain an LHS expression, return (we only handle explicit assignment/initialization).
  4. Get the memory region for LHS:
     - const MemRegion *R = getMemRegionFromExpr(LHS, C).
     - If R is null, return.
  5. Arm the checker for the next branch:
     - State = C.getState()->set<LastAllocRegion>(R);
     - C.addTransition(State).
  6. This arm means “the immediate next encountered branch condition should be the NULL-check for R; if it checks some different pointer (especially a sibling field), flag a mismatch.”

B) checkBranchCondition — verify the next NULL check matches the just-allocated target
- Goal: On the very next branch after an allocation assignment, see if the condition is a NULL-check on the same region. If it checks a different pointer (especially a sibling field) and looks like an error path (e.g., returning -ENOMEM), report.
- Steps:
  1. Load the armed region:
     - const MemRegion *RAlloc = State->get<LastAllocRegion>();
     - If null, do nothing (no pending allocation), return.
  2. Extract the pointer expression being NULL-checked from the Condition:
     - Let E = nullptr initially.
     - If Condition is a UnaryOperator with opcode UO_LNot, set E = operand.
     - Else if Condition is a BinaryOperator (== or !=):
       - Try to evaluate one side to int using EvaluateExprToInt; if it evaluates to 0, the other side is the pointer expression E.
     - Else if Condition looks like a raw pointer used as boolean (e.g., if (ptr)):
       - Set E = cast<Expr>(Condition) (ignore implicit casts).
     - Else if macros like unlikely()/likely() wrap things:
       - Use findSpecificTypeInChildren<UnaryOperator> on Condition to find ‘!’ case; or findSpecificTypeInChildren<BinaryOperator> for ==/!= with 0; pick the first suitable inner form to get E.
     - If we fail to find an E, we will consider this branch unrelated; clear the arm (see step 6) and return.
  3. Get region of the checked expression:
     - const MemRegion *RChecked = getMemRegionFromExpr(E, C);
     - If null, treat as unrelated; clear arm and return.
  4. If RChecked == RAlloc:
     - Correct check: clear the arm (set LastAllocRegion to null) and return.
  5. If RChecked != RAlloc, apply a sibling-heuristic to reduce noise:
     - If both regions are FieldRegion, compare their super regions:
       - auto *F1 = dyn_cast<FieldRegion>(RAlloc); auto *F2 = dyn_cast<FieldRegion>(RChecked);
       - If F1 && F2 && F1->getSuperRegion() == F2->getSuperRegion(), then they are fields of the same parent object (e.g., dst->thread.sve_state vs. dst->thread.za_state). This strongly suggests a mismatched check after allocation.
     - If the above sibling check fails, consider this unrelated; clear the arm and return (keeps the checker precise).
  6. Check that the if-then branch is an error path (to further cut down FPs):
     - Find the IfStmt containing this condition using findSpecificTypeInParents<IfStmt>(Condition, C).
     - From IfStmt->getThen(), use findSpecificTypeInChildren<ReturnStmt>().
     - If there is a ReturnStmt, inspect its return expression:
       - If ExprHasName(ReturnExpr, "ENOMEM", C) is true, consider it an ENOMEM error path.
       - Optionally also accept a negative constant return (via EvaluateExprToInt and checking sign), but ENOMEM check is often sufficient.
     - If no error-return is detected, do not report; clear the arm and return.
  7. Report bug:
     - Create a non-fatal error node with generateNonFatalErrorNode.
     - Build a short message, including field names if available:
       - If RAlloc and RChecked are FieldRegion, use FieldRegion->getDecl()->getName() to form: “Mismatched NULL check: allocated ‘sve_state’ but checked ‘za_state’.”
       - Otherwise: “Mismatched NULL check: checking a different pointer than the just-allocated one.”
     - Emit report via std::make_unique<PathSensitiveBugReport>.
  8. Regardless of reporting, clear the arm:
     - State = State->set<LastAllocRegion>(nullptr); C.addTransition(State).

C) checkEndFunction — cleanup
- Clear any pending state at function end:
  - If LastAllocRegion is set, clear it (set to nullptr) to avoid carrying across analyses.

3) Notes on helper usage and conservatism

- Allocator identification: use getCalleeIdentifier()->getName() and compare with a small fixed set of names.
- LHS extraction:
  - Use findSpecificTypeInParents<BinaryOperator> (opcode BO_Assign) or findSpecificTypeInParents<DeclStmt>.
  - Handle MemberExpr/DeclRefExpr as LHS targets; ignore complex cases (keep it simple).
- Region comparison and sibling heuristic:
  - Use getMemRegionFromExpr to get regions. For FieldRegion, compare getSuperRegion pointers to confirm both are fields of the same base object.
- Error-path heuristic:
  - Require a ReturnStmt in the then-branch returning ENOMEM (via ExprHasName(..., "ENOMEM", C)) to avoid false positives.
- Immediate-next-branch policy:
  - The arm is always cleared on the first branch condition encountered after an allocation assignment, whether it matches or not. This focuses the checker on the specific pattern of “allocate X; if (!Y) return -ENOMEM;” right after.

4) Bug report message

- Keep it short and clear:
  - “Mismatched NULL check after allocation: allocated ‘<alloc-field>’ but checked ‘<checked-field>’.”
  - If field names can’t be extracted: “Mismatched NULL check after allocation.”
