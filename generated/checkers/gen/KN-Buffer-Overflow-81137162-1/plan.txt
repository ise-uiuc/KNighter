1) Program state
- No custom program state is required. The bug is detectable at call sites using AST/type information only.

2) Callbacks and overall flow
- Use only checkPreCall. Inspect calls to strcpy/__builtin_strcpy, analyze destination and source expressions, and emit a report if the destination is a fixed-size array and the copy is unbounded or provably too large.

3) Detailed steps for checkPreCall
- Identify target calls:
  - If Call.getCalleeIdentifier() name equals "strcpy" or "__builtin_strcpy", proceed.
  - Ensure the call has exactly 2 arguments.

- Extract arguments:
  - const Expr *Dest = Call.getArgExpr(0);
  - const Expr *Src  = Call.getArgExpr(1);

- Compute destination buffer size (compile-time, array only):
  - Normalize expression: E = Dest->IgnoreParenImpCasts().
  - If E is a UnaryOperator with opcode UO_ArrayToPointerDecay, set E = E->getSubExpr()->IgnoreParenImpCasts().
  - Case A: E is DeclRefExpr to a variable with ConstantArrayType:
    - Use provided getArraySizeFromExpr(ArraySize, E) to obtain size (element count).
  - Case B: E is MemberExpr to a field:
    - Retrieve FieldDecl *FD = cast<FieldDecl>(ME->getMemberDecl()).
    - QualType FT = FD->getType(); if dyn_cast<ConstantArrayType>(FT.getTypePtr()) succeeds, get its size (element count) as DestSize.
  - Otherwise (not a constant array, e.g., pointer param, flexible array member, VLA), skip (no report) to reduce false positives.

- Try to determine source length (optional refinement):
  - First, check for string literal:
    - If getStringSize(SrcLen, Src) succeeds, remember that string literal length is contents length; strcpy will also copy the null terminator, so effective bytes copied = SrcLen + 1.
  - Otherwise, try to identify if source is a constant-size array:
    - Similar normalization as destination:
      - If Src->IgnoreParenImpCasts() is UO_ArrayToPointerDecay, inspect subexpression.
      - If subexpression is DeclRefExpr or MemberExpr to ConstantArrayType, extract SrcSize as its element count. For char arrays, the maximum bytes copied can be up to SrcSize (if fully filled including null).
  - If none apply, source length is unknown/unbounded.

- Decide and report:
  - If source is string literal and (SrcLen + 1) > DestSize: definite overflow.
    - Emit bug: "strcpy overflows fixed-size buffer".
  - Else if source is a constant array and SrcSize > DestSize: likely overflow.
    - Emit bug: "strcpy may overflow fixed-size buffer".
  - Else (source length unknown) but destination is a fixed-size array: unbounded copy into fixed-size buffer.
    - Emit bug: "Unbounded strcpy into fixed-size buffer; possible overflow".
  - For all reports:
    - Create a non-fatal error node with C.generateNonFatalErrorNode().
    - Use a static BugType, e.g., "Unchecked string copy into fixed-size buffer".
    - Build a PathSensitiveBugReport. Keep message short and clear. Optionally include sizes if known, e.g., "dest size=8".
    - Highlight the call expression range, and optionally add a note range on the destination argument.

4) Helper utilities to implement
- bool isStrcpyCall(const CallEvent &Call):
  - Return true if callee identifier is "strcpy" or "__builtin_strcpy".

- bool getConstantArraySizeFromExpr(const Expr *E, llvm::APInt &Size):
  - Try provided getArraySizeFromExpr(Size, E) first.
  - Else, unwrap ArrayToPointerDecay and check MemberExpr:
    - If MemberExpr, get FieldDecl type; if ConstantArrayType, set Size to its size and return true.
  - Else, unwrap to DeclRefExpr and check if its type is ConstantArrayType; if so, extract size.
  - Return false if none matched.

- Optional: format a brief suffix string with known sizes for the report message:
  - If DestSize known, append "(dest size=N)".
  - If SrcLen literal known, append "(src literal length=L)".

5) False positive control
- Only warn when the destination is a compile-time constant array (ConstantArrayType).
- Do not warn when destination is a pointer (cannot know size).
- Do not warn if the source is a string literal whose length+1 fits in the destination (safe).
- Do not warn for bounded APIs (strlcpy/strscpy/strncpy) — simply ignore them in isStrcpyCall.

6) Optional enhancements (keep simple for initial version)
- Also flag strcat/__builtin_strcat using the exact same logic, as it is also unbounded. This can be added by extending isStrcpyCall to recognize "strcat"/"__builtin_strcat".
- If desired, include a brief fix-it hint in the message: "Use strscpy(dest, src, sizeof(dest))".
