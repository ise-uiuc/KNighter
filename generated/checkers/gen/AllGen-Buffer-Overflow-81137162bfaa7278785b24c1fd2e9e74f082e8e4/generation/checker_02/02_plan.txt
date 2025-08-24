Plan

1. Program state
- No custom program state is required. This checker is a syntactic/semantic call-site check for unsafe string copies. We will not model flows or aliases.

2. Helper logic (inside the checker)
- getConstArrayBound(const Expr *E): Given an expression E (destination or source), try to recover a compile-time constant array bound.
  - Use E->IgnoreParenImpCasts() to strip array-to-pointer decay and other casts.
  - If the underlying expression is a DeclRefExpr or a MemberExpr, read its QualType.
  - If the QualType is a ConstantArrayType, extract the size via cast<ConstantArrayType>(QT.getTypePtr())->getSize().
  - Return true on success (and set an APInt out-param), false otherwise.
- getStringLiteralLen(const Expr *E): Use the provided getStringSize to retrieve the length of a string literal argument. Note that for overflow with strcpy, check len + 1 > destSize to account for the terminating null.
- getFunctionName(const CallEvent &Call): Extract the callee IdentifierInfo and return its name for simple string comparison.
- isStrcpyLike(const CallEvent &Call): Return true if the callee is one of:
  - "strcpy"
  - "__builtin_strcpy"
  Note: Do NOT warn on "strscpy", "strlcpy", or bounded copy functions.

3. Callback selection and implementation

3.1. checkPreCall (main detection)
- Goal: Detect calls to strcpy where the destination is a fixed-size buffer (compile-time known bound) and the copy is unbounded.
- Steps:
  1) Recognize the target function:
     - If !isStrcpyLike(Call), return.
     - Ensure the call has at least 2 arguments.
  2) Extract arguments:
     - const Expr *Dst = Call.getArgExpr(0);
     - const Expr *Src = Call.getArgExpr(1);
  3) Derive destination bound:
     - APInt DstSize;
     - Try getConstArrayBound(Dst). If this fails, return without warning (we only warn when we know the destination is a fixed-size array).
  4) Try to reason about source size:
     - APInt SrcStrLen;
     - bool SrcIsStringLiteral = getStringLiteralLen(SrcStrLen, Src).
     - If SrcIsStringLiteral:
       - Compute Needs = SrcStrLen.getLimitedValue() + 1.
       - If Needs > DstSize.getLimitedValue(), report a definite buffer overflow.
       - Else (Needs <= DstSize): considered safe; return.
     - Else (not a string literal):
       - Try to get a constant array bound for the source:
         - APInt SrcArrBound;
         - If getConstArrayBound(Src) succeeds and Src is a char-array:
           - The array’s total bound is an upper bound on content including the null terminator if initialized from a literal.
           - If SrcArrBound.getLimitedValue() > DstSize.getLimitedValue(), report potential overflow (cannot prove content length, but capacity exceeds destination).
           - Else return (likely safe in practice).
       - Otherwise (unknown source length):
         - Report potential overflow because strcpy is unbounded and the destination has a fixed, small bound.
  5) Reporting:
     - Use generateNonFatalErrorNode to create a node. If null, return.
     - Create a PathSensitiveBugReport (short message):
       - Definite case: "strcpy overflows fixed-size buffer"
       - Potential case: "strcpy into fixed-size buffer may overflow; use strscpy(..., sizeof(dest))"
     - Add source range of the call or the destination argument to the report for highlighting.
     - Optionally include a note describing the destination size (e.g., "destination buffer size is 8").
     - Emit with C.emitReport.

3.2. Optional suppression (simple and conservative)
- To avoid some false positives, perform a very simple guard check just before reporting:
  - If the immediate surrounding if-condition compares strlen(Src) against a constant or sizeof(dest), we can skip the warning when the check ensures source length < DstSize.
  - Implementation (optional, only if you want to be slightly conservative):
    - Use findSpecificTypeInParents<IfStmt>(CallExpr) via the provided upward utility (findSpecificTypeInParents) to locate an enclosing IfStmt whose condition contains strlen(Src) and a bound comparable to DstSize.
    - This is optional; if complexity is undesired, skip this suppression to keep the checker simple.

4. What we warn on
- Only when destination has a compile-time bound (constant array) and the function is strcpy (or builtin variant).
- Definite overflow if source is a string literal with len + 1 > dest size.
- Potential overflow if:
  - Source length is unknown, or
  - Source is a constant array with capacity > dest size.

5. What we do not track
- No pointer aliasing or path-sensitive null checks required.
- No custom program state maps; no checkBind, checkLocation, etc.
- No post-call modeling is necessary.

6. Notes aligning to the provided patch
- The kernel patch replaces strcpy(di.name, hdev->name) with strscpy(di.name, hdev->name, sizeof(di.name)).
- Our checker will flag exactly this pattern because:
  - dest (di.name) is a fixed-size array (e.g., 8).
  - source length is unknown (hdev->name can be longer).
  - We will report: "strcpy into fixed-size buffer may overflow; use strscpy(..., sizeof(dest))".
