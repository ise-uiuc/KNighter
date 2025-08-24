Plan

1) Program state
- No custom program state is required. The checker is a call-site inspection for unsafe API usage with locally derivable facts (array bound and literal length).

2) Callbacks
- Use only checkPreCall to inspect calls to strcpy and decide whether the destination is a fixed-size array and the copy is unbounded/too large.

3) Helper routines
- isStrcpyLike(const CallEvent &Call):
  - Return true if Call.getCalleeIdentifier() exists and its name equals "strcpy".
  - Do not match strlcpy/strscpy/etc.

- getFixedArrayBoundFromArg(const Expr *Arg, CheckerContext &C, llvm::APInt &Bound):
  - Goal: Given the destination argument expression, recover the underlying fixed-size array bound, if any.
  - Steps:
    - Let E = Arg->IgnoreParenImpCasts().
    - If Arg is an ImplicitCastExpr with CK_ArrayToPointerDecay, let A = ICE->getSubExpr()->IgnoreParenImpCasts().
    - Inspect A->getType(). If it is a ConstantArrayType (CAT), set Bound = CAT->getSize() and return true.
    - This handles:
      - DeclRefExpr where the variable is a fixed-size array (char buf[8]).
      - MemberExpr (e.g., di.name) where the field type is a ConstantArrayType (char name[8]).
    - Otherwise return false (no known fixed bound).

- getExactStringLiteralLength(const Expr *Arg, CheckerContext &C, llvm::APInt &Len):
  - Use provided getStringSize(StringSize, Arg) utility.
  - Note: StringLiteral::getLength() returns the number of characters excluding the terminating NUL. For strcpy, the required bytes are Len + 1.

4) checkPreCall implementation
- Recognize target call:
  - If not isStrcpyLike(Call), return.
- Extract arguments:
  - const Expr *Dst = Call.getArgExpr(0), *Src = Call.getArgExpr(1).
- Determine destination fixed-size bound:
  - llvm::APInt DstBound;
  - If getFixedArrayBoundFromArg(Dst, C, DstBound) is false, return (we only warn when we know the destination is a fixed-size array).
- Determine source size characteristics:
  - Case A: String literal:
    - llvm::APInt SrcLen;
    - If getExactStringLiteralLength(Src, C, SrcLen) is true:
      - Required = SrcLen + 1 (to account for NUL).
      - If Required.ugt(DstBound):
        - Report bug: "strcpy overflows fixed-size buffer".
        - Include a note suggesting: "Use strscpy(dst, src, sizeof(dst))."
      - Else (Required <= DstBound): treat as safe; do nothing.
  - Case B: Non-literal source (unknown or variable length):
    - Since strcpy is unbounded and destination is a known fixed-size array, report a potential overflow.
    - Message: "Unbounded strcpy into fixed-size buffer may overflow."
    - Add a note: "Use strscpy(dst, src, sizeof(dst))."
- Bug reporting:
  - Create a BugType once (e.g., “Possible buffer overflow (strcpy into fixed-size buffer)”).
  - Create an error node via generateNonFatalErrorNode().
  - Report using std::make_unique<PathSensitiveBugReport>.
  - Highlight the destination argument source range.

5) Scope of detection and false positives handling
- Only warn when the destination is conclusively a fixed-size array (ConstantArrayType) to minimize false positives.
- If the source is a string literal and fits (including NUL), do not warn.
- If the source is not a literal (cannot prove upper bound), warn because strcpy provides no bound and may overflow a fixed-size destination.
- No additional branch-condition inspection is needed for this pattern (keep the checker simple as requested).

6) Notes on utility usage and AST details
- Use getStringSize for literal length extraction.
- For array bound extraction, rely on identifying CK_ArrayToPointerDecay on the destination argument and reading the ConstantArrayType from the decayed subexpression’s type. This works for both DeclRefExpr (local arrays) and MemberExpr (struct fields like di.name[8]).
- No alias or pointer state tracking is necessary, as we only decide based on the callsite’s destination type and source expression kind.

7) Summary of minimal implementation steps
- No REGISTER_* program state.
- Implement isStrcpyLike, getFixedArrayBoundFromArg, getExactStringLiteralLength helpers.
- Hook checkPreCall:
  - If call is strcpy:
    - If destination is a fixed array:
      - If source is a string literal and length+1 > sizeof(dest): report.
      - Else if source is not a string literal: report (potential overflow).
- Keep report messages short and suggest strscpy(dst, src, sizeof(dst)).
