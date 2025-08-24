Plan

1. No custom program state
- Do not register any custom traits or maps. This checker can be implemented with a single AST-pattern check around branch conditions, using the provided helpers to walk parents/children and to obtain MemRegions.

2. Callback selection
- Use only checkBranchCondition. This is sufficient to:
  - Detect “NULL-check-like” conditions.
  - Find the immediately preceding statement within the same block.
  - Verify that statement is an allocation assignment.
  - Compare the checked pointer with the allocated lvalue and diagnose a mismatch.

3. Detailed implementation of checkBranchCondition
3.1. Recognize a NULL-check condition
- Given the Condition stmt pointer, obtain the expression CE = dyn_cast<Expr>(Condition)->IgnoreParenImpCasts().
- Extract the pointer expression CheckedE from CE if CE matches any of:
  - UnaryOperator UO_LNot: !X → CheckedE = X->IgnoreParenImpCasts().
  - BinaryOperator BO_EQ: (X == 0 or X == NULL) or (0 == X or NULL == X) → CheckedE = the non-constant/null side.
  - Optionally, handle BO_NE with the same logic only if you want to catch non-null checks; to reduce false positives, prefer only the “null-check-like” patterns above.
- If none match, return.

3.2. Locate the IfStmt and the immediately previous statement in the same compound block
- Use findSpecificTypeInParents<IfStmt>(Condition, C) to get the enclosing IfStmt SIf; if not found, return.
- Use findSpecificTypeInParents<CompoundStmt>(SIf, C) to get the enclosing block Comp; if not found, return.
- Iterate Comp->body() to find SIf’s index i; if i == 0, return (no previous statement).
- Let PrevS = Comp->body()[i-1]; This is the statement just before the if-statement in the same block.

3.3. Ensure the previous statement is an assignment from an allocation call
- Check if PrevS is a BinaryOperator with opcode BO_Assign. If not, return.
- Let Assign = cast<BinaryOperator>(PrevS).
  - LHS = Assign->getLHS()->IgnoreParenImpCasts().
  - RHS = Assign->getRHS()->IgnoreParenImpCasts().
- Verify RHS is a CallExpr CECall; if not, return.
- Extract callee name (IdentifierInfo) and check if it is an allocation-like function:
  - Allowed names (expandable): kzalloc, kvzalloc, kmalloc, kcalloc, kmemdup, krealloc, devm_kzalloc, devm_kmalloc, devm_kcalloc.
  - If not in the set, return.

3.4. Compare the pointer being NULL-checked with the just-allocated lvalue
- Obtain MemRegions for both expressions:
  - RegionAlloc = getMemRegionFromExpr(LHS, C).
  - RegionChecked = getMemRegionFromExpr(CheckedE, C).
- If either is null, return (insufficient info).
- We want to catch the specific bug “allocated one field, checked a different field (sibling)”. Do:
  - Try casting both to FieldRegion:
    - const auto *FRAlloc = dyn_cast<FieldRegion>(RegionAlloc).
    - const auto *FRChecked = dyn_cast<FieldRegion>(RegionChecked).
  - If both are FieldRegion:
    - If FRAlloc == FRChecked: correct check → return.
    - Else, compare their immediate super regions:
      - If FRAlloc->getSuperRegion() == FRChecked->getSuperRegion():
        - They are siblings in the same parent object (e.g. dst->thread.sve_state vs dst->thread.za_state).
        - This matches the target bug pattern → report.
      - Else return (not the specific pattern).
  - Otherwise (non-field regions), you may skip reporting to minimize false positives. If desired, as an optional relaxed heuristic:
    - Compare textual bases using ExprHasName to see if both share the same base prefix before the last “->” or “.” and differ in the last field name; only then report. By default, keep it disabled for precision.

3.5. Optional additional filter to reduce false positives
- Check the then-branch of SIf (SIf->getThen()):
  - If it contains an immediate ReturnStmt (possibly in a CompoundStmt of one statement) returning some error (commonly -ENOMEM), this strengthens the confidence.
  - You can attempt to detect a negative integer literal with EvaluateExprToInt, but error codes are often macros; skip strict checks if it’s too restrictive.

3.6. Reporting
- If the mismatch is confirmed:
  - Create a bug type: “Wrong NULL check after allocation”.
  - Generate a non-fatal error node and emit a PathSensitiveBugReport.
  - Message: “Wrong NULL check: checking ‘X’ after allocating ‘Y’.”
    - Extract X and Y from source text via Lexer using the Exprs CheckedE and LHS (or use ExprHasName to confirm names).
  - Attach the primary location to the condition expression CheckedE’s source range.

4. Utility functions to use
- findSpecificTypeInParents to get the surrounding IfStmt and its CompoundStmt.
- getMemRegionFromExpr to compare regions and super-regions.
- ExprHasName optionally for relaxed textual checks.
- EvaluateExprToInt optionally for return value inspection (not required).

5. Notes and scope
- This checker focuses on the immediate-pattern: “alloc into field” immediately followed by “if (!different_field) …”.
- Keeping it block-local and requiring adjacency avoids heavy program-state logic and significantly reduces false positives.
- Extend the alloc function name set as needed for broader kernel coverage.
