1) Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(ShortenMap, const VarDecl*, const VarDecl*)
  - Key: the VarDecl of the “shorten-like” variable.
  - Value: the VarDecl of the iov_iter pointer variable used to compute it.
- REGISTER_SET_WITH_PROGRAMSTATE(SafeShortenSet, const VarDecl*)
  - Contains “shorten-like” variables that are guarded by a comparison against iter->count.

2) Callbacks and implementation details

Step A — Record risky “shorten-like” definitions
- Use both:
  - checkPostStmt(const DeclStmt *DS, CheckerContext &C)
  - checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
- In checkPostStmt:
  - For each VarDecl VD in DS with an initializer:
    - If the initializer is a BinaryOperator BO with opcode BO_Sub:
      - Let L = BO->getLHS(), R = BO->getRHS().
      - Require that L contains the call “iov_iter_count(…)” and R contains the name “round_up”:
        - Use ExprHasName(L, "iov_iter_count") and ExprHasName(R, "round_up").
      - Extract the iov_iter variable used:
        - From the call “iov_iter_count(arg)”, find arg’s DeclRefExpr via findSpecificTypeInChildren<DeclRefExpr>(L) and get its VarDecl* IterVD.
      - Ensure VD’s type is unsigned (VD->getType()->isUnsignedIntegerType()).
      - Record ShortenMap = ShortenMap->set(VD, IterVD).
- In checkBind:
  - Also catch non-declarative assignments “shorten = iov_iter_count(iter) - round_up(…)”:
    - If S is a BinaryOperator with opcode BO_Assign:
      - If RHS is BO_Sub and matches ExprHasName(lhs, "iov_iter_count") and ExprHasName(rhs, "round_up"):
        - Extract LHS DeclRefExpr “shorten” VarDecl* ShortenVD.
        - Extract iov_iter arg VarDecl* IterVD as above.
        - Check ShortenVD is unsigned.
        - Record in ShortenMap(ShortenVD -> IterVD).

Step B — Mark when there is a guard
- checkBranchCondition(const Stmt *Cond, CheckerContext &C)
  - If Cond is a BinaryOperator with opcode BO_GE or BO_GT:
    - Identify if it compares a “shorten-like” variable against “iter->count”.
      - One side must be a DeclRefExpr ShortenDRE; get ShortenVD.
      - Other side must be a MemberExpr to field named “count”. From that MemberExpr, get the base expression’s DeclRefExpr IterDRE and its VarDecl* IterVD.
      - Check that ShortenVD exists in ShortenMap and ShortenMap[ShortenVD] == IterVD.
    - If so, insert ShortenVD into SafeShortenSet (consider this as a sufficient guard).

Step C — Detect and report the unsafe subtraction into iter->count
- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
  - Case 1: Compound subtract “iter->count -= shorten”
    - If S is a CompoundAssignOperator with opcode BO_SubAssign:
      - LHS must be a MemberExpr to a field named “count”.
      - RHS must be a DeclRefExpr to some VarDecl* ShortenVD.
      - Extract iter variable from LHS base DeclRefExpr IterVD.
      - If ShortenMap contains ShortenVD and ShortenMap[ShortenVD] == IterVD and ShortenVD not in SafeShortenSet:
        - Report bug: “Possible unsigned underflow: subtracting a round_up(...) difference from iter->count without bounds check.”
        - Use generateNonFatalErrorNode and emit a PathSensitiveBugReport.
        - Optionally erase ShortenVD from ShortenMap to avoid duplicate reports.
  - Case 2: Simple assign “iter->count = iter->count - shorten”
    - If S is a BinaryOperator with opcode BO_Assign:
      - LHS must be a MemberExpr to field named “count”.
      - RHS must be a BinaryOperator BO_Sub whose LHS is syntactically the same MemberExpr as the assignment LHS and whose RHS is a DeclRefExpr ShortenVD.
      - Extract IterVD from LHS base DeclRefExpr.
      - Check ShortenMap[ShortenVD] == IterVD and ShortenVD not in SafeShortenSet, then report as above and optionally erase.

Notes:
- Use findSpecificTypeInChildren<DeclRefExpr>(…) to extract DeclRefExprs from both the iov_iter_count argument and from MemberExpr bases.
- Use ExprHasName to detect “iov_iter_count” and “round_up”. This is robust even if round_up is a macro.
- Only warn when:
  - The “shorten-like” variable is unsigned.
  - It is computed as iov_iter_count(iter) - round_up(...).
  - It is later used to reduce iter->count for the same iter.
  - No guard was seen comparing shorten against iter->count with >= or >.

Step D — Cleanup
- No special cleanup needed; ProgramState is scoped per path/function. If desired, remove a ShortenVD from ShortenMap after reporting to suppress duplicates within a path.

3) Bug report
- Use a short message:
  - “Possible size underflow: round_up(...) may exceed iov_iter_count(); subtracting it from iter->count can wrap.”
- Attach the subtraction statement’s SourceRange. Optionally, add a note at the “shorten = iov_iter_count(...) - round_up(...);” definition site if available by using the checker context’s source range on the initializer/assignment.
