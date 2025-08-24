Plan

1. Program state
- No custom program state is necessary. This checker is a local call-usage checker that inspects each strcpy call’s arguments and their types/sizes.

2. Callback functions
- Use only checkPreCall. Everything can be determined at the moment of the call.

3. checkPreCall: detect unsafe strcpy into fixed-size arrays
- Goal: Warn when strcpy copies into a fixed-size character array whose capacity is known (e.g., di.name[8]) and the source length is not provably smaller than the destination capacity. This covers the bug pattern of unbounded copy into fixed-size buffers.
- Steps:
  a) Identify strcpy:
     - Get the callee identifier via Call.getCalleeIdentifier(). If null, return.
     - If name != "strcpy", return.

  b) Retrieve destination (arg 0) and determine if it is a decayed fixed-size array:
     - Let Dest = Call.getArgExpr(0).
     - Peel implicit casts: If Dest is an ImplicitCastExpr with cast kind CK_ArrayToPointerDecay, then get the underlying array expression Arr = cast<ImplicitCastExpr>(Dest)->getSubExpr()->IgnoreParenImpCasts().
     - Determine the array type and its size:
       - QualType QT = Arr->getType().
       - const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr()).
       - If CAT is null, the destination is not a compile-time fixed-size array; return (to reduce false positives).
       - Check that the element type is a character type: CAT->getElementType() is ‘char’, ‘signed char’, or ‘unsigned char’. If not char-like, return.
       - Extract DestSize = CAT->getSize() (APInt).

     - Note: If Dest is not an ImplicitCastExpr with ArrayToPointerDecay, you can still check if Dest->IgnoreParenImpCasts() has array type (rare). Prefer the decay path.

  c) Estimate the source length or bound:
     - Let Src = Call.getArgExpr(1).
     - Fast-path: StringLiteral
       - If Src is a StringLiteral (via provided getStringSize(StringSize, Src)), compute SrcLen = StringSize (length without null terminator).
       - If SrcLen >= DestSize (APInt comparison), emit a bug (since strcpy copies the terminating ‘\0’, strings of length >= DestSize overflow).
       - If SrcLen < DestSize, consider safe and return.
     - Otherwise, try to detect a compile-time fixed-size source array (optional improvement; see note):
       - If Src is also an ArrayToPointerDecay of a ConstantArrayType (same approach as for Dest), you can compute SrcCap = source array capacity. However, array capacity is not a strict upper bound of string length (string can be up to capacity-1), so you cannot prove safety from this alone. For simplicity and to align with the target pattern, do not suppress the warning based on source capacity. Proceed to the next step.
     - Otherwise (unknown or non-literal source):
       - Treat as potentially unbounded. Since Dest is a fixed-size array and strcpy is unbounded, emit a warning.

  d) Bug reporting:
     - Create a BugType (e.g., "Unbounded string copy into fixed-size buffer") once in the checker.
     - Generate a non-fatal error node with C.generateNonFatalErrorNode().
     - Emit a PathSensitiveBugReport with a short message, e.g.:
       - "strcpy to fixed-size buffer may overflow; use strscpy(dest, src, sizeof(dest))."
     - Attach the call expression’s source range as the location/range to highlight.

4. Helper logic details (within checkPreCall)
- Function identification:
  - Use Call.getCalleeIdentifier()->getName() == "strcpy".

- Determining fixed-size array destination (robust handling):
  - Primary method: Look for ImplicitCastExpr of CK_ArrayToPointerDecay on arg0; then read the subexpression’s type as ConstantArrayType.
  - If needed, also handle Dest->IgnoreParenImpCasts() whose type is ConstantArrayType (edge cases).
  - Ensure the element type is character-like (char/signed char/unsigned char) to avoid false positives on non-string arrays.

- String literal length:
  - Use provided getStringSize(StringSize, Src). Length excludes the null-terminator. Compare as:
    - If StringSize >= DestSize => overflow (report).
    - Else safe (no report).

- Optional suppression (keep simple for initial version):
  - Only suppress if source is a string literal with length strictly less than destination capacity.
  - For all other sources (unknown, pointers, struct member arrays, etc.) consider unsafe and report.

5. Why this is sufficient for the target patch
- The buggy code uses strcpy(di.name, hdev->name) where di.name is a fixed-size array of length 8. The destination will be recognized as a decayed ConstantArrayType with size 8. The source is not a string literal, so the checker will emit a warning advising to use strscpy(..., ..., sizeof(dest)), matching the provided fix.

6. Notes
- No need to track aliases or data flow: the decision is local to each strcpy call.
- No need to model post-call state.
- Keep the checker narrow to reduce FPs: only warn when destination capacity is known at compile-time (ConstantArrayType). This precisely targets the class of bugs fixed by switching to strscpy with sizeof(dest).
