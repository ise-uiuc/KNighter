```
Plan: Detect unbounded copy_from_user() into fixed-size buffers

1) Program state customization
- Not necessary. This checker can be implemented without custom program states or traits.

2) Callbacks to use
- checkPreCall: Main detection of unsafe copy_from_user() usage.

3) Detailed steps

A. Helper predicates/utilities to implement (local in checker)
- bool isCopyFromUser(const CallEvent &Call):
  - Return true if Call.getCalleeIdentifier()->getName() == "copy_from_user".

- bool getDestArrayAndSize(const Expr *DestArg, std::string &BufName, llvm::APInt &ArraySize):
  - Use getArraySizeFromExpr(ArraySize, DestArg) to obtain the constant array size.
  - If success, also extract the variable name:
    - If DestArg (after IgnoreImplicit/IgnoreParenImpCasts) is a DeclRefExpr to a VarDecl, set BufName = VD->getNameAsString().
  - Return true if both array size and name were obtained.

- bool exprIsStaticallyBoundedByBufMinusOne(const Expr *LenExpr, StringRef BufName, unsigned BufSize, CheckerContext &C):
  - Try exact reasoning first:
    - If EvaluateExprToInt(EvalRes, LenExpr, C) succeeds:
      - Return true if EvalRes <= (BufSize - 1), else false.
    - Else try to obtain a max bound using the analyzer’s symbolic reasoning:
      - Get SVal of LenExpr via C.getState()->getSVal(LenExpr, C.getLocationContext()).
      - If it has a SymbolRef, call inferSymbolMaxVal(Sym, C).
        - If maxVal exists, return true if maxVal <= (BufSize - 1); else false.
  - If still unknown, apply simple structural/textual heuristics to avoid false positives:
    - If ExprHasName(LenExpr, "min", C) and (ExprHasName(LenExpr, "sizeof", C) or ExprHasName(LenExpr, BufName, C)):
      - Consider it bounded, return true.
    - If ExprHasName(LenExpr, "sizeof", C) and ExprHasName(LenExpr, BufName, C):
      - If the source text contains "- 1" as well, consider it bounded, return true.
  - Otherwise, return false (not proven bounded).

- Optional helper: bool exprLooksLikeRawUserLen(const Expr *LenExpr, CheckerContext &C):
  - If LenExpr is a DeclRefExpr to a parameter or local named typically "nbytes", "len", "count", or "size", return true.
  - Else return false.
  - This is only used to bias reporting when we cannot prove boundedness.

B. Implementation in checkPreCall(const CallEvent &Call, CheckerContext &C) const
- If not isCopyFromUser(Call), return.
- Retrieve arguments:
  - const Expr *DestArg = Call.getArgExpr(0);
  - const Expr *LenExpr = Call.getArgExpr(2);
  - If either is null, return.

- Determine if destination is a fixed-size array:
  - std::string BufName; llvm::APInt ArraySize;
  - If !getDestArrayAndSize(DestArg, BufName, ArraySize), return.
  - If ArraySize == 0, return (defensive guard).
  - unsigned BufSize = ArraySize.getLimitedValue(); if BufSize == 0, return.

- Check whether the length is safely bounded by sizeof(buf)-1:
  - if (exprIsStaticallyBoundedByBufMinusOne(LenExpr, BufName, BufSize, C)) return; // safe, no report

- If not proven safe, reduce false positives:
  - If EvaluateExprToInt(LenExpr) succeeded and the constant is <= BufSize, still unsafe per our pattern if it’s exactly BufSize (no room for terminator). Proceed to warn only if it’s > BufSize - 1.
  - If symbolic max is known and <= BufSize - 1, do not warn.
  - Otherwise, if exprLooksLikeRawUserLen(LenExpr, C) is true, proceed to warn.
  - If none of the above applies (completely unknown), do not warn to avoid noise.

- Reporting:
  - Create an error node via generateNonFatalErrorNode().
  - Emit a PathSensitiveBugReport with a short message like:
    - "copy_from_user length not bounded by sizeof(buffer) - 1; possible overflow"
  - Highlight DestArg and LenExpr ranges to aid the user.
  - One report per call site.

4) Notes to keep it simple and effective
- We target the common kernel anti-pattern: passing unvalidated user length (e.g., nbytes) directly to copy_from_user for a fixed-size local buffer.
- We only warn when the destination is a compile-time constant array and the length is not proven (symbolically or syntactically) to be bounded by sizeof(buf) - 1.
- We leverage:
  - getArraySizeFromExpr to obtain array size.
  - EvaluateExprToInt and inferSymbolMaxVal to reason about length.
  - ExprHasName to heuristically detect min/sizeof(buf)-1 patterns and avoid false positives.
- No alias/pointer tracking or additional program state is needed.

5) Optional extension (can be skipped for minimal viable checker)
- Detect the good pattern: len = min(nbytes, sizeof(buf) - 1); if copy_from_user(..., len) is used but the function returns the original nbytes instead of len, optionally warn about "returned size not clamped," though this is beyond the core overflow detection.
```
