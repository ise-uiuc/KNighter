1) Program state
- No custom program state is needed. The pattern is a purely semantic/typing issue (where the arithmetic is performed in a narrower integer type and only later widened). We can detect it reliably from the AST and type information.

2) Callback functions and detailed implementation

A) checkPostStmt(const BinaryOperator *B) const
- Goal: Detect a multiplication that is computed in 32-bit (or generally <64-bit) and only later converted to a 64-bit integer.
- Steps:
  1. Filter to multiplication:
     - If B->getOpcode() != BO_Mul, return.
     - If !B->getType()->isIntegerType(), return.
  2. Get the bit-width of the multiplication’s resulting type:
     - unsigned MulWidth = C.getASTContext().getIntWidth(B->getType());
     - If MulWidth >= 64, return (the multiply already happens in a 64-bit type; safe).
  3. Check operands (optional sanity; not strictly required since the result width already encodes the effective arithmetic width):
     - Both operands should be integer types. If not, return.
  4. Determine if the result of this multiply is used in a 64-bit integer context:
     - Search upwards for any of these parents with destination 64-bit integer type:
       - ImplicitCastExpr (IntegralCast, IntegralToBoolean won’t be 64-bit; we want integral cast to a 64-bit integer)
       - CStyleCastExpr
       - CXXStaticCastExpr / CXXFunctionalCastExpr
     - For each of these types, use findSpecificTypeInParents<T>(B, C). If found, check the cast’s target type:
       - If the cast’s target is an integer type with width >= 64, mark as “widened use”.
     - If no cast found, also check for the broader contexts which imply a 64-bit destination (in case the CastExpr was optimized away or doesn’t exist as a node near the expression):
       - Assignment: Find a parent BinaryOperator that is an assignment (isAssignmentOp()). If found and its LHS type is integer with width >= 64, mark as “widened use”.
       - Return: Find a parent ReturnStmt. If found, get the current function’s return type from C.getLocationContext()->getDecl()->getReturnType() and check width >= 64.
       - Function argument: Find a parent CallExpr; if found, try to see if this multiply expression is used as a direct argument:
         - Iterate the call’s arguments; if any arg expression pointer (after IgnoreParenImpCasts) is equal to B or contains B as its immediate expression, and the corresponding parameter type is integer with width >= 64, mark as “widened use”.
         - Note: In most cases a 64-bit argument will introduce an ImplicitCastExpr parent above the multiply; therefore this is a fallback. If it’s too complex to reliably match the argument, you can skip this step since the ImplicitCastExpr search will catch the common cases.
     - If no “widened use” is found, return.
  5. Optional false-positive reduction (prove no 32-bit overflow can occur):
     - Extract LHS and RHS operands: const Expr *E1 = B->getLHS(); const Expr *E2 = B->getRHS();
     - Try to determine maximum possible values:
       - If EvaluateExprToInt(C1, E1, C) succeeds, we have a constant for E1; otherwise, try symbol max with inferSymbolMaxVal on E1’s symbol.
       - Do the same for E2.
     - If you get concrete maxima for both sides (U1 and U2, treating as unsigned if types are unsigned), compute U1 * U2 using 64-bit arithmetic and check if the product fits in 32 bits (<= 0xFFFFFFFF for unsigned). If it definitely fits, do not warn.
     - If you cannot retrieve both maxima, or the computed product exceeds 32-bit range, proceed to warn.
  6. Emit a bug report:
     - Create a BugType once (e.g., "Narrow multiply widened after overflow").
     - Create a BasicBugReport with a short message:
       - "32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply."
     - Highlight the source range of the multiplication (B->getSourceRange()).
     - Use C.emitReport(std::make_unique<BasicBugReport>(...)).

Notes and rationale:
- Checking B->getType() gives the effective arithmetic type after usual integer promotions and usual arithmetic conversions. If that type’s width is 32 and the parent context widens to 64, the multiply was indeed computed in 32-bit first.
- Looking for any parent CastExpr to 64-bit captures:
  - Assignment to u64 fields/vars (there is typically an implicit cast on the RHS),
  - Returning u64 from a function,
  - Passing the multiply result to a u64 parameter.
- If an explicit cast surrounds the multiply, e.g., (u64)(a*b), we still warn because the multiply occurred in 32-bit before the explicit cast.
- The optional range reasoning uses provided utilities to reduce noise when both operands’ maxima ensure the product fits in 32 bits.

B) No other callbacks required
- The multiply-then-widen pattern is most reliably caught at the multiply node itself via checkPostStmt(const BinaryOperator*).
- DeclStmt/ReturnStmt/Call checks are indirectly covered via parent CastExpr detection. If desired, implement the function-argument fallback described above; otherwise you can rely on ImplicitCastExprs to catch the common cases.

3) Small helper logic (as comments in the checker)
- Helper to get integer width and signedness:
  - Use C.getASTContext().getIntWidth(QualType) and Ty->isUnsignedIntegerType() to understand widths and signedness.
- Parent search:
  - Use the provided findSpecificTypeInParents<T>(...) repeatedly for ImplicitCastExpr, CStyleCastExpr, CXXStaticCastExpr, BinaryOperator (assignment), ReturnStmt, and CallExpr.

4) Report message
- Keep it short and actionable:
  - "32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply."
