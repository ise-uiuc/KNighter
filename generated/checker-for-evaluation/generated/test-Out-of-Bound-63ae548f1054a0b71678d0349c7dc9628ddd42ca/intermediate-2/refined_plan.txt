Your plan here

1. Determine the need for a custom program state
  • No custom program state maps are needed. The bug pattern is localized to an array subscript without a prior bound check, so we can perform a direct evaluation of the index expression at the moment of the array access.

2. Choose the callback function: checkLocation
  • In the checkLocation callback (which is invoked on a load or store from a location), inspect the statement (S) to see if it corresponds to an array access into a transfer function points array.
  • Use the helper function ExprHasName() on the statement’s source text to check for the substring "tf_pts" (or "output_tf->tf_pts") indicating that the array accessed is the one of interest.

3. Locate the array subscript and extract the index
  • Use the utility function findSpecificTypeInChildren with the appropriate type (e.g. an ArraySubscriptExpr) on the statement S. This helps you navigate downward in the AST and obtain the node that represents the array subscript.
  • From the ArraySubscriptExpr, extract the subscript (the index expression).

4. Evaluate the index expression
  • Call EvaluateExprToInt() on the extracted index expression. If evaluation yields a constant integer value, compare it to the constant TRANSFER_FUNC_POINTS (you can assume its value is exposed or hardcode it for the purpose of the check).
  • If the evaluated index is greater than or equal to TRANSFER_FUNC_POINTS, then the array indexing is unchecked and may lead to out-of-bounds access.

5. Report the bug
  • Use the bug reporting utilities (for example, create a bug report with std::make_unique<BasicBugReport> or PathSensitiveBugReport) with a short, clear message (e.g., "Unchecked array indexing: index value may exceed TRANSFER_FUNC_POINTS").
  • Emit the report using the CheckerContext (C.emitReport(...)).

6. Summary of the implementation in checkLocation
  • In the checkLocation callback, check if S (or its associated children via findSpecificTypeInChildren) is an ArraySubscriptExpr referring to the tf_pts array.
  • Evaluate the index from the subscript expression.
  • If the index is not safely within [0, TRANSFER_FUNC_POINTS), issue an error report.
  • This simple approach does not require additional state tracking or aliasing analysis.

This straightforward plan should let you write a checker that, when an array subscript operation on the transfer function points array is encountered, evaluates the subscript and flags a potential buffer overflow if the index is not properly bounded.