Plan

1. Program state customization
- Define two maps to track the “shorten” variable and whether it has been safely bounded before use:
  - REGISTER_MAP_WITH_PROGRAMSTATE(ShortenIterMap, const VarDecl*, const VarDecl*)
    - Key: VarDecl* of the “shorten” variable (or any variable assigned the shrink amount).
    - Value: VarDecl* of the iov_iter variable used to derive the shrink amount (the argument to iov_iter_count() or the base of iter->count).
  - REGISTER_MAP_WITH_PROGRAMSTATE(ShortenGuardedMap, const VarDecl*, bool)
    - Key: VarDecl* of the “shorten” variable.
    - Value: true if there is a guard like “shorten >= iter->count” (or strict variants) seen on the current path before subtracting; false otherwise.

2. Helper matching utilities (internal to the checker)
- getIterVarFromCountExpr(const Expr* E) -> const VarDecl*
  - Return the VarDecl of the iter variable if E is either:
    - CallExpr callee name “iov_iter_count” with a single DeclRefExpr argument; return its VarDecl.
    - MemberExpr with member name “count” and base as DeclRefExpr; return base VarDecl.
  - Otherwise, return nullptr.
- isSubOfIterCount(const Expr *E, const VarDecl* &OutIter) -> bool
  - If E is a BinaryOperator with opcode BO_Sub:
    - Try getIterVarFromCountExpr on the LHS; if non-null, set OutIter and return true.
  - Otherwise false.
- isIterCountMemberExprForVar(const Expr *E, const VarDecl *IterVD) -> bool
  - If E is a MemberExpr with member name “count” and base is DeclRefExpr referring to IterVD, return true.
- getShortenVarFromExpr(const Expr *E) -> const VarDecl*
  - If E contains a DeclRefExpr referring to a local VarDecl, return its VarDecl.
- isUnsignedSizeLike(QualType T) -> bool
  - Return T->isUnsignedIntegerType() to ensure we’re dealing with size_t-like unsigned.

3. checkPostStmt(const DeclStmt* DS)
- Goal: Record “shorten” variables created via declarations with initializers of the form iov_iter_count(iter) - something OR iter->count - something.
- Steps:
  - For each VarDecl VD in DS:
    - If VD->hasInit():
      - Let Init = VD->getInit()->IgnoreParenImpCasts().
      - If isSubOfIterCount(Init, IterVD) is true and VD->getType() is unsigned integer (isUnsignedSizeLike), update state:
        - State = State->set<ShortenIterMap>(VD, IterVD)
        - State = State->set<ShortenGuardedMap>(VD, false)
        - C.addTransition(State)

4. checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
- Part A: Also record “shorten” when assigned later (not just declared).
  - If S is a BinaryOperator with opcode BO_Assign:
    - LHS: if it’s a DeclRefExpr to VarDecl VD, and VD->getType() is unsigned:
      - RHS = BO->getRHS()->IgnoreParenImpCasts()
      - If isSubOfIterCount(RHS, IterVD) is true:
        - State = State->set<ShortenIterMap>(VD, IterVD)
        - State = State->set<ShortenGuardedMap>(VD, false)
        - C.addTransition(State)
- Part B: Detect decrement of iter->count by “shorten” without prior bounding.
  - Handle two shapes:
    1) CompoundAssignOperator (iter->count -= shorten):
      - If S is CompoundAssignOperator CAO and CAO->getOpcode() == BO_SubAssign:
        - LHS is MemberExpr ME: base should be DeclRefExpr to IterVD.
        - RHS contains a DeclRefExpr to some VarDecl ShortenVD.
        - Check if ShortenVD exists in ShortenIterMap and maps to IterVD.
        - Check ShortenGuardedMap[ShortenVD] == false.
        - If all true, report bug (see step 6).
    2) BinaryOperator assignment (iter->count = iter->count - shorten):
      - If S is BinaryOperator BO with opcode BO_Assign:
        - LHS must be MemberExpr ME equal to iter->count for some IterVD.
        - RHS is BinaryOperator Sub with LHS equal to the same iter->count MemberExpr and RHS DeclRefExpr to ShortenVD.
        - Check ShortenIterMap[ShortenVD] == IterVD and ShortenGuardedMap[ShortenVD] == false.
        - If all true, report bug.

5. checkBranchCondition(const Stmt *Condition, CheckerContext &C)
- Goal: Mark “shorten” as guarded if a bounding check is present on the path.
- Recognize common guard patterns:
  - If Condition is BinaryOperator with op >= or > (or their symmetric forms):
    - Pattern A: shorten >= iter->count (or >)
      - Try to identify ShortenVD on one side:
        - If side contains a DeclRefExpr to a VarDecl ShortenVD that exists in ShortenIterMap:
          - On the other side, check isIterCountMemberExprForVar(side, IterVDMapped) where IterVDMapped = ShortenIterMap[ShortenVD].
          - If yes, mark bounded:
            - State = State->set<ShortenGuardedMap>(ShortenVD, true)
            - C.addTransition(State)
    - Pattern B: round_up(...) > iov_iter_count(iter) (optional, broader coverage)
      - If one side’s expression text contains “iov_iter_count” and resolves to IterVD X via getIterVarFromCountExpr, and the other side contains “round_up”, then for every ShortenVD in ShortenIterMap mapping to IterVD X:
        - State = State->set<ShortenGuardedMap>(ShortenVD, true)
        - C.addTransition(State)
- Notes:
  - Use both AST matching (preferred) and textual fallback via ExprHasName when encountering macros/inlines. For example, if callee cannot be resolved, use ExprHasName(E, "iov_iter_count", C).

6. Bug reporting
- When an unsafe decrement is detected in checkBind:
  - Create a non-fatal error node: if (!N) return; to avoid duplicate reports.
  - Message: “Possible underflow: iter->count decreased by unbounded size_t shorten.”
  - Create a PathSensitiveBugReport with a succinct description:
    - Title: “Unbounded iov_iter count decrement may underflow”
    - Description: “round_up(...) can exceed available count; subtracting into size_t underflows iter->count.”
  - Attach the statement S as the location.
  - Optionally, add notes pointing to:
    - The declaration/assignment of ShortenVD (if available) and
    - The missing/absent guard (if ShortenGuardedMap is false on this path).
  - Emit the report.

7. Minimizing false positives
- Only flag when:
  - The LHS being decremented is exactly iter->count for the same IterVD recorded from the shorten computation.
  - The shrink variable is an unsigned integer (size_t-like).
  - No guard observed on the current path: ShortenGuardedMap[ShortenVD] is false.
- Do not emit when a guard is present:
  - If we saw a guard condition of the recognized forms on this path, we set ShortenGuardedMap to true and thus suppress the warning.

8. Callbacks summary and roles
- checkPostStmt(DeclStmt): Record “shorten = iov_iter_count(iter) - …” or “shorten = iter->count - …”.
- checkBind:
  - Record “shorten” on assignment form.
  - Detect “iter->count -= shorten;” or “iter->count = iter->count - shorten;” and report if unguarded.
- checkBranchCondition: Mark “shorten” as guarded for conditions like “shorten >= iter->count” (preferred) or “round_up(...) > iov_iter_count(iter)”.
- No other callbacks are necessary.

This plan detects the specific unsafe pattern where a size_t shrink amount derived from iov_iter_count/iter->count is subtracted from iter->count without bounding, which could underflow when the rounded-up length exceeds the available count.
