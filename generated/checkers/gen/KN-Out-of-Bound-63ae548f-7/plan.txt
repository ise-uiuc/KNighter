1) Program state
- No custom program-state traits or maps are required. We will rely on:
  - The analyzer’s path-sensitive constraints via inferSymbolMaxVal.
  - Local AST queries for constant array bounds and nearby guards.

2) Callbacks to use
- checkLocation: Main detection of potentially OOB array subscripts.
- check::BranchCondition (optional, lightweight): Only to leverage the analyzer’s normal constraint splitting; no custom state is recorded.
- No other callbacks are necessary.

3) Detailed steps

Step A. Detect risky array subscripts at memory access (checkLocation)
- Trigger: Each load/store will invoke checkLocation. If S is an ArraySubscriptExpr (ASE), analyze it. If not, return.
  - Retrieve ASE via dyn_cast<ArraySubscriptExpr>(S).
- Compute the constant bound of the array:
  - Let Base = ASE->getBase()->IgnoreParenImpCasts().
  - Extract its type: QualType BT = Base->getType().
  - If BT is a ConstantArrayType (auto *CAT = dyn_cast<ConstantArrayType>(BT.getTypePtr())), then get CAT->getSize() as ArrayBound.
  - If not a constant-size array, skip (return). We only target fixed-size LUT arrays to reduce noise.
- Heuristic to focus on the target pattern (reduce false positives):
  - If ExprHasName(Base, "tf_pts", C) is true, continue. Otherwise, you may skip to reduce noise and match the target bug pattern (array lies under tf_pts.{red,green,blue}).
    - Optionally also allow MemberExpr chains whose final field names are “red”, “green”, or “blue” to broaden matching within the same structure, but “tf_pts” is the most specific and sufficient for this patch.
- Get the index expression:
  - const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts().
- Determine whether the index is provably within bounds:
  1) Constant evaluation:
     - Try EvaluateExprToInt(IdxVal, Idx, C). If true and IdxVal >= ArrayBound, report a bug (definite OOB).
     - If IdxVal < ArrayBound, safe; return.
  2) Symbolic evaluation:
     - Retrieve SymbolRef for the index: SVal IdxSVal = C.getSVal(Idx); SymbolRef IdxSym = IdxSVal.getAsSymbol(); If no symbol, return (unknown, do not warn).
     - Use inferSymbolMaxVal(IdxSym, C). If it returns a value MaxVal:
       - If MaxVal < ArrayBound, it is proven safe on this path; return.
       - If MaxVal >= ArrayBound, it is potentially unsafe; proceed to the next bullet to check for an explicit guard in nearby conditions.
     - If inferSymbolMaxVal returns null (no inferred max), this is unknown and suspect; proceed to the next bullet to check for an explicit guard in nearby conditions.
- Suppress if an explicit guard against TRANSFER_FUNC_POINTS exists nearby:
  - Try to find a nearby guard that constrains Idx against TRANSFER_FUNC_POINTS.
  - Check the nearest parent IfStmt (using findSpecificTypeInParents<IfStmt>(S, C)). If found, inspect its condition:
    - Extract the index variable’s source text name (for DeclRefExpr index, IdxDRE->getDecl()->getName()).
    - Use ExprHasName(IfStmt->getCond(), IndexVarName, C) AND ExprHasName(IfStmt->getCond(), "TRANSFER_FUNC_POINTS", C).
    - If both names appear in the same condition (e.g., i < TRANSFER_FUNC_POINTS, i <= TRANSFER_FUNC_POINTS - 1, i >= TRANSFER_FUNC_POINTS), then assume this path has/handles the guard; skip warning.
  - If no IfStmt found or no such condition, also look at parent loop conditions:
    - For parent ForStmt/WhileStmt, similarly check if the loop condition contains both the index var name and “TRANSFER_FUNC_POINTS”. If yes, skip warning.
- If we reach here, we have:
  - A fixed-size LUT array indexed by a computed index (often from region math).
  - No proven constraint that index < array bound on the current path.
  - No explicit guard against TRANSFER_FUNC_POINTS in a dominating condition.
  - Emit a warning.

Reporting (in checkLocation)
- Create a non-fatal error node with C.generateNonFatalErrorNode().
- Emit a PathSensitiveBugReport with a short message, e.g.:
  - “Possible out-of-bounds LUT access: index is not checked against TRANSFER_FUNC_POINTS.”
- Use the ArraySubscriptExpr as the report location.

4) Notes and implementation specifics
- Constraint reasoning:
  - Rely on inferSymbolMaxVal to learn if current path ensures i < N. If the added check (i >= TRANSFER_FUNC_POINTS) { return false; } is present, the analyzer will split states; on the fall-through path inferSymbolMaxVal will return <= N-1, and the checker won’t warn.
- Bound extraction:
  - We intentionally restrict to constant-sized arrays via ConstantArrayType to avoid false positives on pointer arithmetic.
- Pattern focus:
  - Restricting to bases that contain “tf_pts” via ExprHasName keeps the checker tightly targeted to the LUT pattern in this patch. If broader coverage is desired, drop that filter, but expect more noise.
- Utility functions used:
  - EvaluateExprToInt: to resolve constant index i.
  - inferSymbolMaxVal: to query solver constraints for max(i).
  - ExprHasName: to detect use of names like “tf_pts”, “TRANSFER_FUNC_POINTS”, and the index variable within conditions.
  - findSpecificTypeInParents: to identify enclosing IfStmt and loop statements for nearby guards.
- No need to track aliases or custom program state, since we only analyze the current ASE and the solver constraints on its index.

5) Callback summary
- checkLocation:
  - If S is ArraySubscriptExpr on a ConstantArrayType base and base text contains “tf_pts”:
    - Derive bound N, resolve index value/range.
    - If not provably < N and there is no nearby guard using TRANSFER_FUNC_POINTS, emit report.
- check::BranchCondition:
  - No custom logic required; rely on analyzer constraints. No state updates.
