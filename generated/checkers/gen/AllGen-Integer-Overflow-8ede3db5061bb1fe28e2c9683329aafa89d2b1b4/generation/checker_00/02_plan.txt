1) Program state
- No custom program state is needed. The bug is a local, purely syntactic/type-mismatch pattern at a single callsite.

2) Callbacks and implementation steps
- Use only checkPreCall. This is sufficient to analyze the callsite of check_add_overflow() and its arguments.

Step A — Identify the target call
- In checkPreCall(const CallEvent &Call, CheckerContext &C):
  - Get callee identifier via Call.getCalleeIdentifier(); return if null.
  - If name != "check_add_overflow", return.
  - Ensure there are exactly 3 arguments.
  - Let ResArg = Call.getArgExpr(2). Get its type and assert it’s a pointer type.
  - Let ResTy = ResArg->getType()->getPointeeType(). If ResTy is not an integer type, return. If it’s an unsigned integer type, return (the reported pattern requires a signed destination).
  - Record ResTyCanonical = ResTy.getCanonicalType(), and compute ResWidthBits = C.getASTContext().getTypeSize(ResTy).

Step B — Detect the suspicious narrowing signed cast on operands
- For each of the first two arguments (i = 0, 1):
  - Let E = Call.getArgExpr(i)->IgnoreParens() (do not ignore explicit casts).
  - Check if E is an explicit cast expression:
    - Prefer dyn_cast<ExplicitCastExpr>(E). This matches CStyleCastExpr and C++ explicit casts. If it is not an ExplicitCastExpr, continue to next argument.
  - Let CastDestTy = CastExpr->getType().getCanonicalType().
  - Require:
    - CastDestTy is an integer type and isSignedIntegerType().
    - CastDestTy is the same as ResTyCanonical (the result pointer’s base type).
  - Let Sub = CastExpr->getSubExpr()->IgnoreImpCasts(); let SubTy = Sub->getType().getCanonicalType().
  - Require:
    - SubTy is an integer type and SubTy isUnsignedIntegerType().
    - Compute SubWidthBits = C.getASTContext().getTypeSize(SubTy).
    - SubWidthBits > ResWidthBits (this ensures the cast is a narrowing from a wider unsigned type, like size_t, to a narrower signed type, like int).
  - If all conditions hold, this argument is suspicious.

Step C — Report once per callsite
- If either argument 0 or 1 is suspicious (as per Step B), emit a bug report:
  - Create a BugType once (e.g., checker member) named "Overflow check defeated by narrowing cast".
  - Generate a non-fatal error node: if (!N) return; N = C.generateNonFatalErrorNode().
  - Message: "Narrowing cast to signed type before check_add_overflow may hide overflow; avoid casting size-related values to int."
  - Highlight the explicit cast source range (use the ExplicitCastExpr’s source range).
  - Use PathSensitiveBugReport with the created BugType and message, and emit via C.emitReport().

Notes and heuristics
- This checker intentionally requires the explicit cast destination type to match the result pointer’s base integer type (e.g., int). This keeps the signal precise and directly matches the kernel bug pattern:
  - Bad: check_add_overflow(hdr, (int)controllen, &hdr) where hdr is int.
  - Bad: check_add_overflow((int)sizeof(...), namelen, &hdr) where hdr is int.
- The check covers both operands. If both are suspicious, report once for the first encountered; this avoids duplicate diagnostics per callsite.
- The first-argument sizeof case is naturally handled because sizeof returns a size_t-typed expression (unsigned, usually wider than int), and an explicit cast to int meets the heuristic.

Utility functions usage
- No program state utility needed.
- Use C.getASTContext() to get type sizes for the narrowing check.
- No taint or alias analysis is involved.
- Optionally use ExprHasName if you later generalize to detect other overflow helpers, but not needed for the current plan.

Chosen callbacks summary
- checkPreCall:
  - Match "check_add_overflow".
  - Extract result pointer pointee type; require signed integer.
  - Detect explicit cast of an unsigned wider integer to the same signed type as the result (int) in either operand.
  - Report with concise message and highlight the cast.
