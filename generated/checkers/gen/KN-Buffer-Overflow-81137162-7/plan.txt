Plan

1) Program state
- No custom program state is needed. This is a local, call-site pattern: detect unbounded copy into a fixed-size struct field and report immediately when found.

2) Callback functions
- Use only checkPreCall. This is sufficient to inspect the function call, extract the destination/source, reason about sizes, and report.

3) checkPreCall (detailed steps)
- Identify target calls:
  - Get the callee identifier via Call.getCalleeIdentifier().
  - If the name equals "strcpy", proceed; otherwise return.

- Validate argument count:
  - Ensure there are at least 2 arguments (dest, src). If not, return.

- Extract and analyze the destination argument (dest):
  - Let DestArg = Call.getArgExpr(0).
  - Goal: Confirm dest is a struct/union field of constant array type (the bug pattern).
  - Use findSpecificTypeInChildren<MemberExpr>(DestArg) to find the MemberExpr that represents the field access (e.g., di.name).
    - If not found, do not report (we only target fixed-size struct/union fields).
  - From MemberExpr, get the FieldDecl (FD) via getMemberDecl().
  - Obtain the canonical type of the field: QualType FT = FD->getType().
    - Check if FT is a ConstantArrayType. If not, return (we only target fixed-size arrays).
    - If ConstantArrayType (CAT), record:
      - DestElemTy = CAT->getElementType().
      - DestSize = CAT->getSize() (llvm::APInt).
    - Optionally restrict to character arrays:
      - If DestElemTy is not a char-like type (BuiltinType::Char_S, Char_U, SChar, UChar, or typedef that resolves to char), return. Otherwise proceed.

- Extract and analyze the source argument (src):
  - Let SrcArg = Call.getArgExpr(1).
  - Try to compute a definite-safe case first:
    - If SrcArg is a StringLiteral (use getStringSize utility on SrcArg):
      - Let SL = string length (without null terminator).
      - Required = SL + 1 (for the null terminator).
      - If Required <= DestSize, then it’s provably safe; return without reporting.
      - Else, report a definite overflow (see Reporting below).
  - If not a StringLiteral, try to get an upper-bound estimate from a fixed array source:
    - Attempt to find MemberExpr for SrcArg: ME2 = findSpecificTypeInChildren<MemberExpr>(SrcArg).
      - If ME2 exists and refers to a FieldDecl whose type is ConstantArrayType, extract SrcSize = CAT2->getSize().
      - If SrcSize > DestSize, report (likely overflow).
    - Else, attempt to get a fixed size from a local/global array source:
      - Use getArraySizeFromExpr on SrcArg. If it returns a size SrcSize and SrcSize > DestSize, report (likely overflow).
  - If the source is neither a fitting StringLiteral nor a fixed array with known size:
    - It is an unbounded/unknown-length source copied into a fixed-size struct field with strcpy. Report a potential overflow and suggest bounded copy.

- Reporting
  - Create a BugType once (e.g., in the checker constructor or lazily) named "Unbounded string copy to fixed-size buffer".
  - Generate a non-fatal error node via C.generateNonFatalErrorNode().
  - Build a PathSensitiveBugReport:
    - Message:
      - If StringLiteral too long: "strcpy overflows fixed-size field".
      - Else: "strcpy into fixed-size struct field may overflow; use strscpy(..., sizeof(dest))".
    - Add the source range of the call, and optionally the dest argument range, as the report location.
  - Emit report via C.emitReport(...).

4) Helper routines (internal to the checker)
- bool isStrcpyCall(const CallEvent &Call):
  - Return true if Call.getCalleeIdentifier() exists and name equals "strcpy".
- bool getFixedArraySizeFromStructField(const Expr *E, llvm::APInt &Size, QualType &ElemTy):
  - Use findSpecificTypeInChildren<MemberExpr>(E).
  - If found and FieldDecl type is ConstantArrayType, set Size and ElemTy and return true. Else return false.
- bool isCharArrayType(QualType ElemTy):
  - Return true if ElemTy is (canonical) character type: Char_S, Char_U, SChar, UChar, or typedef resolving to these.
- Optional: bool getConstArraySizeFromExpr(const Expr *E, llvm::APInt &Size):
  - First try getArraySizeFromExpr(Size, E) using the provided utility (works for DeclRefExpr to arrays).
  - If that fails, try MemberExpr path similarly to the destination.

5) Heuristics to reduce false positives
- Only report when destination is a struct/union field of fixed-size char array (matches the target pattern).
- Suppress reports if source is a StringLiteral that fits (stringLen + 1 <= destSize).
- Otherwise, conservatively report when the source is unknown or has a known larger bound.

6) Chosen callbacks summary
- checkPreCall:
  - Detect calls to strcpy.
  - Determine if dest is a fixed-size struct field array.
  - If so, assess source length/upper bound (StringLiteral or array bound).
  - Report if overflow is definite or possible.
- No other callbacks are required.
