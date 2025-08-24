1) Program state
- No custom program state is needed. This checker is a pure API misuse pattern match on a single call site.

2) Callback selection and implementation

- checkPreCall (the only callback needed)
  - Goal: Detect calls to memdup_user() where the size argument is a multiplication of a count and an element size (typically sizeof(...)), and suggest using memdup_array_user() instead.
  - Steps:
    1. Identify memdup_user:
       - If Call.getCalleeIdentifier() is null, return.
       - If Call.getCalleeIdentifier()->getName() != "memdup_user", return.
       - Ensure there are at least 2 arguments.
    2. Obtain and normalize the size argument:
       - const Expr *SizeArg = Call.getArgExpr(1)->IgnoreParenImpCasts().
    3. Match “count * elem_size”:
       - Primary pattern:
         - If SizeArg is a BinaryOperator with opcode BO_Mul:
           - Let LHS = BO->getLHS()->IgnoreParenImpCasts()
           - Let RHS = BO->getRHS()->IgnoreParenImpCasts()
           - Check if either LHS or RHS is a sizeof expression:
             - dyn_cast<UnaryExprOrTypeTraitExpr>(Op) and Op->getKind() == UETT_SizeOf
             - If either side is sizeof(...), we have a match.
       - Fallback heuristic (for robustness if the compiler constant-folded the expression or it’s an unusual form):
         - If the above check doesn’t match, use ExprHasName(SizeArg, "sizeof", C) to look for “sizeof” in the source text of the size expression. If present together with a '*' token in the textual range, consider it a match.
           - You can grab the text via the provided utility ExprHasName and also do a lightweight string search for '*' inside the same CharSourceRange using Lexer::getSourceText (similar to ExprHasName’s logic).
    4. Report:
       - If matched, create a non-fatal error node via generateNonFatalErrorNode().
       - Create a PathSensitiveBugReport (or BasicBugReport if preferred) with a short message:
         - "Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count * elem_size); multiplication may overflow."
       - Highlight the size expression range (the second argument) in the report.
       - emit the report.

3) Helper functions (internal to the checker)
- bool isMulWithSizeof(const Expr *E, CheckerContext &C):
  - Returns true if E is a BinaryOperator ‘*’ and one operand is a UnaryExprOrTypeTraitExpr of kind UETT_SizeOf.
- bool looksLikeMulWithSizeofTextual(const Expr *E, CheckerContext &C):
  - Uses ExprHasName(E, "sizeof", C) and a raw source-text “*” search within the expression’s CharSourceRange as a fallback when AST node patterns don’t directly match (e.g., because of casts/parentheses/macros).

4) Notes to keep it simple and precise
- Do not attempt dataflow or alias tracking.
- Do not try to detect and suppress warnings when manual overflow checks exist nearby; keep the checker simple as requested.
- Only trigger for memdup_user. Do not flag memdup_array_user or other allocation APIs.
- Consider both operand orders (sizeof(...) * count and count * sizeof(...)).
- Use IgnoreParenImpCasts when inspecting operands to avoid noise.
- Prefer checkPreCall: no need to model return values or state.
