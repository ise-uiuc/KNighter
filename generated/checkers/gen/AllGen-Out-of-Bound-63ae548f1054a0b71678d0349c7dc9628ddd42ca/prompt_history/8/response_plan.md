Plan: Detect unguarded indexing into output_tf->tf_pts.{red,green,blue}[i] without proving i < TRANSFER_FUNC_POINTS

1) Program state
- No custom program state traits or maps are necessary. We will rely on the analyzer’s built-in constraint manager to reason about index ranges (via inferSymbolMaxVal) and only report when safety cannot be proven.

2) Callbacks and their roles
- checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const
  - Purpose: Trigger on array element loads of the tf_pts channels. The buggy pattern is a read from fixed-size lookup tables with a computed index i that is not validated against the array size (TRANSFER_FUNC_POINTS).
  - Steps to implement:
    1. Early filter: Only act on loads (IsLoad == true).
    2. Identify the array access:
       - dyn_cast the Stmt S to ArraySubscriptExpr (ASE). If not, return.
       - Extract the base expression of ASE: Base = ASE->getBase()->IgnoreImpCasts().
       - We only care about the three channels of the transfer function:
         - Use the provided ExprHasName utility to check for any of the following on Base:
           - "tf_pts.red"
           - "tf_pts.green"
           - "tf_pts.blue"
         - To avoid duplicate reports for the three channels in the same block, optionally only emit a report when Base contains "tf_pts.red" (this is a simple de-dup heuristic). Otherwise, allow reports for all channels.
       - If none match, return.
    3. Retrieve the bound (TRANSFER_FUNC_POINTS) from the array type:
       - For reliable array size extraction, look at the member declaration type:
         - If Base is a MemberExpr ME, get the field’s declared type: QualType MT = ME->getMemberDecl()->getType().
         - dyn_cast<ConstantArrayType>(MT.getTypePtr()). If null, we cannot get a compile-time bound; return to avoid false positives.
         - Extract the size into an llvm::APInt BoundAP = ArrayType->getSize(); Convert to uint64_t Bound.
    4. Analyze the index expression:
       - Let IdxE = ASE->getIdx()->IgnoreImpCasts().
       - Try to compute a constant value using EvaluateExprToInt(EvalRes, IdxE, C). If success:
         - If EvalRes.isSigned() and EvalRes.isNegative() or EvalRes >= Bound: definitely out-of-bounds → Report.
         - Else: safe → return.
       - Otherwise, retrieve a symbolic bound for the index:
         - SVal IdxSVal = C.getSVal(IdxE);
         - SymbolRef Sym = IdxSVal.getAsSymbol();
         - If Sym is null, we cannot reason, report conservatively (but see step 5 for suppression).
         - Else use inferSymbolMaxVal(Sym, C) to get maxVal:
           - If maxVal exists and maxVal.ule(Bound - 1): proven safe → return.
           - If maxVal is absent or maxVal.uge(Bound): not proven safe or proven unsafe → proceed to report.
       - Note: This leverages the analyzer’s path constraints. If there is a guarding condition like if (i >= TRANSFER_FUNC_POINTS) return; or if (i < TRANSFER_FUNC_POINTS) ..., the constraint manager will refine the max value, and we will not report.
    5. Suppress obvious duplicates:
       - If you chose not to de-dup via the ".red" heuristic, you may keep it simple and accept multiple reports (one per channel). Prefer the simple de-dup heuristic: only report when ExprHasName(Base, "tf_pts.red", C) is true.
    6. Emit the bug report:
       - Create a non-fatal error node: if (!N) N = C.generateNonFatalErrorNode();
       - Message: “Index may exceed TRANSFER_FUNC_POINTS when accessing tf_pts.”
       - Use PathSensitiveBugReport with a short, clear description. Optionally add a note pointing to the index expression.
       - C.emitReport(...).

- No other callbacks are required.
  - We do not need checkBranchCondition: the analyzer’s constraint system will update symbol ranges after branches; inferSymbolMaxVal will reflect that.
  - We do not need checkBind or maps for aliases: the index is an integer expression; aliasing is not relevant here.
  - We do not need checkPreCall/checkPostCall: the bug is not about function effects.

3) Heuristics/Details
- Base identification is done via ExprHasName on the base of ArraySubscriptExpr to focus on the specific pattern tf_pts.{red,green,blue}.
- Array bound extraction:
  - Prefer to use MemberExpr’s FieldDecl type (ConstantArrayType) to get the compile-time bound that originates from TRANSFER_FUNC_POINTS. This avoids relying on macro name strings.
- Soundness vs noise:
  - If you cannot find a ConstantArrayType bound, skip reporting to avoid false positives.
  - If the analyzer proves Idx < Bound via constraints (inferSymbolMaxVal), do not report.
  - Constant index outside range is a definite bug: always report.

4) Summary of detection logic in checkLocation
- S is ArraySubscriptExpr and Base contains “tf_pts.red|green|blue”.
- Array bound (Bound) is available from the member’s ConstantArrayType.
- Index i:
  - If constant and i >= Bound: report.
  - Else if symbol:
    - If maxVal ≤ Bound-1: safe, return.
    - If maxVal ≥ Bound or unknown: report.
- Use a simple de-dup heuristic: only report for “tf_pts.red” to avoid three identical diagnostics per site.

5) Report message
- Title: “Possible out-of-bounds access to tf_pts”
- Description: “Index may exceed TRANSFER_FUNC_POINTS when accessing tf_pts.”
- Keep it short and clear as requested.
