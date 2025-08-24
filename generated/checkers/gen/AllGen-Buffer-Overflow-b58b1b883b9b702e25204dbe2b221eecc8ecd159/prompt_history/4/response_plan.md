Plan

1. Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(DeltaToIterMap, const MemRegion*, const MemRegion*)
  - Key: MemRegion of the temporary “shorten” (or any variable) that stores avail - need.
  - Value: MemRegion of the base iov_iter pointer used to compute avail (the argument to iov_iter_count() or the base of MemberExpr “iter->count”).
- No other traits or maps are necessary. Keep the state minimal and focused on correlating the delta with the specific iter.

2. Helper matchers (small internal utilities)
- bool isIovAvailExpr(const Expr *E, const MemRegion* &IterMR, CheckerContext &C)
  - Return true if E is one of:
    - CallExpr to a function whose name is "iov_iter_count", and has 1 argument; set IterMR = getMemRegionFromExpr(arg0, C).
    - MemberExpr whose member name is "count" (i.e., “iter->count”), and base exists; set IterMR = getMemRegionFromExpr(base, C).
- bool isRoundUpExpr(const Expr *E, CheckerContext &C)
  - Return true if ExprHasName(E, "round_up", C) or ExprHasName(E, "roundup", C).
  - Optionally allow variants like ExprHasName(E, "block_bytes", C) for strengthening, but do not require it.
- const MemRegion* getVarRegionFromExpr(const Expr *E, CheckerContext &C)
  - If E is a DeclRefExpr to a local/param variable, return its MemRegion via getMemRegionFromExpr(E, C).
- const MemRegion* getIterBaseFromMemberExpr(const Expr *LHS, CheckerContext &C)
  - If LHS is a MemberExpr with field name "count" and has a base expression, return getMemRegionFromExpr(base, C).
  - Otherwise, return nullptr.
- bool isUnsignedIntegral(QualType QT)
  - Use QT->isUnsignedIntegerType() to reduce noise (optional but recommended).

3. Record “shorten = avail - need” (DeclStmt)
- Callback: checkPostStmt(const DeclStmt *DS, CheckerContext &C)
  - For each VarDecl in DS:
    - If it has an initializer and the type is unsigned integer (preferably size_t), and the initializer is a BinaryOperator with opcode BO_Sub:
      - Let LHS = BO->getLHS(), RHS = BO->getRHS().
      - Check isIovAvailExpr(LHS, IterMR, C) and isRoundUpExpr(RHS, C).
      - If both match and IterMR != nullptr:
        - Find the MemRegion of this variable via getMemRegionFromExpr(DeclRefExpr to the VarDecl).
        - Insert into DeltaToIterMap: Map[DeltaVarMR] = IterMR.

4. Record “shorten = avail - need” (simple assignment)
- Callback: checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
  - If S is a BinaryOperator of kind BO_Assign:
    - Extract the LHS Expr (destination) and RHS Expr (source) from S via dyn_cast<BinaryOperator>(S).
    - If RHS is a BinaryOperator BO_Sub and type unsigned:
      - If isIovAvailExpr(RHS->getLHS(), IterMR, C) and isRoundUpExpr(RHS->getRHS(), C):
        - Compute DeltaVarMR from the LHS expression via getMemRegionFromExpr(LHS, C).
        - If both regions are valid, Map[DeltaVarMR] = IterMR.

5. Detect dangerous decrement: “iter->count -= shorten” or direct “iter->count -= avail - need”
- Callback: checkPostStmt(const CompoundAssignOperator *CAO, CheckerContext &C)
  - If CAO->getOpcode() == BO_SubAssign:
    - Let LHS = CAO->getLHS(); confirm it’s a MemberExpr named "count".
    - Extract IterMR_LHS = getIterBaseFromMemberExpr(LHS, C). If null, return.
    - Let RHS = CAO->getRHS():
      - Case A: RHS is a DeclRefExpr to some variable:
        - Get DeltaVarMR = getVarRegionFromExpr(RHS, C).
        - Lookup IterMR_Map = DeltaToIterMap[DeltaVarMR].
        - If IterMR_Map != nullptr and IterMR_Map == IterMR_LHS:
          - Report bug: “Possible underflow in count adjustment: round_up() may exceed iov_iter length; clamp before decrement.”
      - Case B: RHS is a BinaryOperator BO_Sub:
        - If isIovAvailExpr(RHS->getLHS(), IterMR_RHS, C) and isRoundUpExpr(RHS->getRHS(), C) and IterMR_RHS == IterMR_LHS:
          - Report bug as above.

6. Detect dangerous assignment form: “iter->count = iter->count - shorten/ (avail - need)”
- Callback: checkPostStmt(const BinaryOperator *BO, CheckerContext &C)
  - If BO->getOpcode() == BO_Assign:
    - If LHS is MemberExpr named "count", get IterMR_LHS.
    - If RHS is a BinaryOperator with opcode BO_Sub:
      - If RHS->getLHS() textually references the same “iter->count” (use MemberExpr match or ExprHasName heuristics) or semantically is the same MemberExpr:
        - For RHS->getRHS():
          - Case A: DeclRefExpr to variable: lookup in DeltaToIterMap and compare IterMRs; if match, report.
          - Case B: BinaryOperator BO_Sub with iov_iter_count/round_up pattern and IterMR matches LHS, report.

7. Reporting
- In the reporting sites above:
  - Create a non-fatal error node with generateNonFatalErrorNode().
  - Use a concise message, e.g.:
    - “Underflow risk: avail - round_up(...) may wrap, then used to decrement iter->count. Add clamp check.”
  - Highlight the RHS expression of the compound assignment or the subtraction expression itself.

8. Notes and simplifications
- This is a pattern checker: it does not rely on runtime values. It looks for:
  - An unsigned delta computed as avail - round_up(...), where avail comes from iov_iter_count(iter) or iter->count.
  - The delta then used to decrement iter->count via “-=” or “= ... - ...”.
- Guard suppression:
  - For simplicity, do not attempt to prove presence of a safe guard (“if (shorten >= iter->count) shorten = 0;” or “if (need > avail) ...”). This avoids complex control-flow reasoning and false suppressions.
  - If desired later, a lightweight heuristic can be added in checkBranchCondition to look for conditions containing both the delta variable name and “iter->count” with a “>=” or “>” operator, but this is optional and not required for a correct first version.
- Extra robustness:
  - Accept both “round_up” and “roundup” names (macro variants).
  - Prefer matching unsigned destination type (size_t-like) to minimize noise.
  - Ensure IterMR equality (the same iter base) to avoid cross-iter false positives.
