Plan

1. Program state
- No custom program state is required. We will rely on the analyzer’s constraint manager (inferSymbolMaxVal) to reason about loop-guarded constraints. This keeps the checker simple and path-sensitive without extra state.

2. Callbacks and core logic
- Use checkPreStmt<const ArraySubscriptExpr>
  - Goal: Detect accesses to output_tf->tf_pts.{red|green|blue}[idx] where idx may exceed the fixed LUT size and no prior bound guarantees exist.
  - Steps:
    1) Filter for the target LUT arrays:
       - Let ASE be the current ArraySubscriptExpr.
       - Extract the uncasted base expression B = ASE->getBase()->IgnoreParenImpCasts().
       - Expect B to be a MemberExpr (ME1) directly referring to a color channel field name: red, green, or blue.
       - Ensure ME1’s base is another MemberExpr (ME0) or expression whose source text contains "tf_pts" (use ExprHasName on ME1->getBase(), with "tf_pts"). This targets output_tf->tf_pts.red (and green/blue).
       - If not matching both the channel name and "tf_pts", return (avoid false positives).
    2) Retrieve the compile-time array bound:
       - From ME1, get the FieldDecl F = cast<FieldDecl>(ME1->getMemberDecl()).
       - Obtain F->getType(). If it is ConstantArrayType, fetch the bound (ArraySize).
       - If not ConstantArrayType (e.g., it decayed to pointer), attempt to inspect F->getTypeSourceInfo()->getType() similarly; if still not constant, return (cannot compare ⇒ no warning).
    3) Confirm we are in a loop to reduce noise (focus on computed loop indices):
       - Find an enclosing ForStmt (or WhileStmt) using findSpecificTypeInParents<ForStmt>(ASE, C) or findSpecificTypeInParents<WhileStmt>(ASE, C). If neither exists, return (skip non-loop indexing to match the pattern).
    4) Analyze the index expression:
       - Let IdxE = ASE->getIdx().
       - Try EvaluateExprToInt on IdxE:
         - If it evaluates to a constant:
           - If constant >= ArraySize, report a definite out-of-bounds access.
           - Else constant < ArraySize: safe; return.
       - Otherwise, obtain the SVal of IdxE: SVal SV = C.getState()->getSVal(IdxE, C.getLocationContext()).
         - Extract SymbolRef Sym = SV.getAsSymbol(). If no symbol is available, conservatively continue (cannot prove safe).
         - Use inferSymbolMaxVal(Sym, C):
           - If a max value Max is obtained:
             - If Max < ArraySize, the access is proven safe on this path; return.
             - Else (Max >= ArraySize), it may overflow; continue to reporting.
           - If no Max (unknown), we cannot prove safety; continue to reporting.
    5) Report the potential OOB:
       - Create a non-fatal error node with generateNonFatalErrorNode.
       - Emit a PathSensitiveBugReport with a short message, e.g.:
         - "Possible out-of-bounds: loop index may exceed LUT size when accessing tf_pts.<color>[i]."
       - Add a note at the ArraySubscriptExpr location. Optionally mention: "Add `if (i >= TRANSFER_FUNC_POINTS) return ...;` guard" in the description.

3. Optional refinements to reduce false positives (simple heuristics)
- Verify index is the loop’s induction variable:
  - For a ForStmt, try to extract the increment expression (e.g., i += inc or ++i) and check if IdxE’s textual representation (ExprHasName) contains that variable’s name. If it does not, skip reporting to stay close to the target pattern.
- Skip if there is an explicit bound guard reachable on this path:
  - Not required to implement explicitly. The constraint manager will already eliminate warnings when the branch condition (e.g., i < TRANSFER_FUNC_POINTS) holds on the current path (inferSymbolMaxVal will return a Max below bound).

4. Why this works for the target bug
- The buggy code uses a computed loop index i derived from start_index and increment, and accesses output_tf->tf_pts.red[i] (and green/blue) without validating i against TRANSFER_FUNC_POINTS. There is also the “j == hw_points - 1” break which does not imply i < TRANSFER_FUNC_POINTS.
- Our checker:
  - Precisely matches tf_pts.{red|green|blue}[...] in loops.
  - Retrieves the compile-time bound from the field’s ConstantArrayType.
  - Uses path constraints to see if i is guaranteed < bound. If not, it reports the potential OOB.
- The fix (adding if (i >= TRANSFER_FUNC_POINTS) return false) would constrain i on the safe path, and our checker would no longer report a warning there.

5. Utility functions used
- ExprHasName to match "tf_pts" and "red|green|blue" in the base expression.
- inferSymbolMaxVal to get an upper bound for the index symbol from path constraints.
- EvaluateExprToInt to handle constant indices.
- findSpecificTypeInParents<ForStmt>/<WhileStmt> to ensure we focus on loop-based indexing.
