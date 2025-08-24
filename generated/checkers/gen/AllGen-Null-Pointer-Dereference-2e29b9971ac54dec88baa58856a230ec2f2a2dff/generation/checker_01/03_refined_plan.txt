1) Program state
- No custom program state is required. The pattern can be detected syntactically by analyzing the IfStmt condition and the immediately preceding statement within the same CompoundStmt.

2) Callbacks to use
- checkBranchCondition: Core detection logic for “NULL-check after allocation,” by inspecting the If condition and the immediately previous statement in the same block.
- (Optional) checkASTCodeBody: Not strictly needed; only checkBranchCondition is sufficient.

3) Detailed steps

A. Helper utilities to implement
- isAllocLikeCall(const CallExpr*):
  - Return true if the callee name is one of: "kzalloc", "kmalloc", "kcalloc", "kvzalloc", "devm_kzalloc", "kmemdup".
- isNullLiteral(const Expr*, CheckerContext&):
  - Return true if expr evaluates to 0 using EvaluateExprToInt or the source text contains "NULL".
- extractCheckedPointerFromCondition(const Expr*, CheckerContext&) -> const Expr*:
  - If condition is:
    - UnaryOperator UO_LNot: return the operand expression.
    - BinaryOperator BO_EQ or BO_NE:
      - If exactly one side is null-literal, return the non-null side.
    - Otherwise return nullptr.
  - Only accept negative NULL check:
    - Return a non-null pointer expr for "!ptr" or "ptr == NULL".
    - For "ptr != NULL", return nullptr (we only flag negative NULL checks).
- getPrevStmtInSameCompound(const IfStmt*, CheckerContext&) -> const Stmt*:
  - Find the parent CompoundStmt using findSpecificTypeInParents<CompoundStmt>(IfStmt).
  - Iterate its body to locate the IfStmt and return the previous statement if it exists; otherwise nullptr.
- getAssignFromStmt(const Stmt*) -> const BinaryOperator*:
  - From a statement (prevStmt), dig down to find an assignment BinaryOperator (BO_Assign).
  - Use findSpecificTypeInChildren<BinaryOperator>(prevStmt) and then check if it is an assignment.
- getAllocCallFromRHS(const Expr*) -> const CallExpr*:
  - From the RHS, dig down with findSpecificTypeInChildren<CallExpr>(RHS). If found, check with isAllocLikeCall.
- getMemRegionOfExpr(const Expr*, CheckerContext&) -> const MemRegion*:
  - Use getMemRegionFromExpr.

B. Detection algorithm in checkBranchCondition
- Input: const Stmt* Condition (the analyzed condition of a branch).
- Step 1: Obtain the enclosing IfStmt:
  - IfStmt* IfS = findSpecificTypeInParents<IfStmt>(Condition, C).
  - If none, return.
- Step 2: Extract the checked pointer expression:
  - const Expr* CheckedPtrExpr = extractCheckedPointerFromCondition(cast<Expr>(Condition), C).
  - If nullptr (not a negative NULL check), return.
- Step 3: Obtain the previous statement in the same block:
  - const Stmt* Prev = getPrevStmtInSameCompound(IfS, C).
  - If nullptr, return.
- Step 4: From Prev, get an assignment to a pointer from an allocation call:
  - const BinaryOperator* BO = getAssignFromStmt(Prev).
  - If nullptr or not BO_Assign, return.
  - const CallExpr* CE = getAllocCallFromRHS(BO->getRHS()).
  - If nullptr (RHS is not an allocation call), return.
- Step 5: Compare LHS region vs checked-pointer region:
  - const MemRegion* LHSReg = getMemRegionOfExpr(BO->getLHS(), C).
  - const MemRegion* CheckReg = getMemRegionOfExpr(CheckedPtrExpr, C).
  - If either region is nullptr, return (be conservative).
  - If LHSReg != CheckReg:
    - Optional: ensure the IF ‘then’ is an error path (reduce noise):
      - const ReturnStmt* RS = findSpecificTypeInChildren<ReturnStmt>(IfS->getThen()).
      - You may also check for a GotoStmt, but Return is sufficient to reduce FPs.
    - If an error path is present (or you choose to report without this filter), then report a bug.
- Step 6: Bug report:
  - Create a BugType: "Incorrect NULL-check after allocation".
  - Message: "Allocated pointer checked via a different pointer; possible missed NULL-check."
  - Use generateNonFatalErrorNode and PathSensitiveBugReport. Add notes:
    - Note at allocation assignment (Prev): "Allocation assigned to this pointer."
    - Note at If condition: "But NULL-check tests a different pointer."

C. Notes and considerations
- Focus on adjacency: Only warn if the allocation assignment is the immediate previous statement to the IfStmt. This strictly matches the target bug and minimizes false positives.
- Negative NULL checks only: "!ptr" or "ptr == NULL". This matches typical out-of-memory error paths like "return -ENOMEM".
- No alias tracking: We rely on MemRegion identity comparison. This is sufficient because the pattern consists of distinct struct fields or variables.
- Functions coverage: Include kzalloc/kmalloc/kcalloc/kvzalloc/devm_kzalloc/kmemdup. You can extend if needed, but this set suffices for kernel allocations and the example.
- Robustness for wrappers: Use findSpecificTypeInChildren to dig into wrappers like ExprWithCleanups so we handle real-world AST shapes.
