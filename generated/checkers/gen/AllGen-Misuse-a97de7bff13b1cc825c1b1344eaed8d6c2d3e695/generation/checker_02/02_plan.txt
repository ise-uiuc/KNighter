Plan

1) Program state
- No custom program state is necessary. This checker is a pure call-pattern detector.

2) Callback selection
- Use checkPostCall as the only callback. We will analyze each function call and report if it matches the bug pattern.

3) Detection in checkPostCall
- Identify target calls:
  - Retrieve the callee’s IdentifierInfo from CallEvent and check if the name equals "copy_from_sockptr".
  - Ignore other function names (e.g., the fixed helper "bt_copy_from_sockptr" is the correct pattern and should not be flagged).

- Collect arguments:
  - For copy_from_sockptr, require at least 3 arguments.
  - Arg0: destination buffer (ignored for decision).
  - Arg1: source sockptr, typically named optval.
  - Arg2: length expression (LenExpr) that we must analyze.

- Require setsockopt context heuristics (to minimize false positives):
  - Ensure we are in a function that has a parameter named "optlen".
    - Get FunctionDecl from C.getLocationContext()->getDecl(), iterate parameters, check getNameAsString() == "optlen".
  - Ensure the 2nd argument’s source text contains "optval" (ExprHasName(Arg1, "optval", C)).

- Decide if the length is a fixed size and not bounded by optlen:
  - Define a small helper (inline in the checker) isFixedSizeExpr(E):
    - Let EE = E->IgnoreParenImpCasts().
    - Return true if EE is:
      - UnaryExprOrTypeTraitExpr with kind UETT_SizeOf, or
      - IntegerLiteral (or CharacterLiteral if present).
  - Check whether LenExpr is bounded by optlen:
    - If ExprHasName(LenExpr, "optlen", C) => bounded, do not warn.
    - Else if LenExpr is a DeclRefExpr to a VarDecl and VarDecl->hasInit():
      - If ExprHasName(VarDecl->getInit(), "optlen", C) => bounded (e.g., len = min(..., optlen)), do not warn.
  - If isFixedSizeExpr(LenExpr) is true and not bounded by optlen as per above checks, then we have the bug pattern.

- Emit report:
  - Create a BugType once in the checker (e.g., BT.reset(new BugType(this, "copy_from_sockptr ignores optlen", "Linux API Misuse"))).
  - Create a non-fatal error node: if (!N) N = C.generateNonFatalErrorNode(); if (!N) return; (standard pattern).
  - Emit a concise message:
    - "copy_from_sockptr size ignores optlen; use bt_copy_from_sockptr or validate optlen"
  - Attach the report to the call expression’s source range:
    - Use Call.getSourceRange() or the third argument source range to highlight.

4) Notes/heuristics to reduce noise
- Only report when:
  - Function has parameter named "optlen", and
  - The second argument contains "optval", and
  - The length (third argument) is a fixed-size expression (sizeof(...) or integer literal) and not bounded/derived from "optlen" by the simple checks above.
- This focuses the checker on setsockopt-like handlers and avoids flagging unrelated copy_from_sockptr uses.

5) Optional enhancements (if desired, but not required)
- Also match "copy_from_sockptr" calls where LenExpr is a DeclRefExpr with no init but later re-assigned; this requires scanning CFG or previous statements and is intentionally omitted to keep the checker simple and robust.
- To extend coverage, you may add "copy_from_sockptr_offset" with appropriate index for the length argument once its signature is confirmed; otherwise, leave it out to avoid false positives.

Callbacks summary
- checkPostCall:
  - If callee is "copy_from_sockptr":
    - Check for presence of function parameter "optlen".
    - Verify Arg1 mentions "optval".
    - Analyze Arg2 (length):
      - If fixed-size and not referencing/derived from "optlen", report the bug.
- No other callbacks are used.
