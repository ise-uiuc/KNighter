Plan

1. Program State
- No custom program state is needed. This checker is a pure call-site/AST inspection that reports immediately when it sees an unbounded string copy into a fixed-size buffer.

2. Callback Functions
- Use only checkPreCall.

3. checkPreCall (core detection)
- Goal: Detect calls to unbounded string-copy APIs that target a fixed-size character array, which enables overflow when the source length may exceed the destination capacity.

- Step-by-step:
  a) Identify unbounded string-copy functions:
     - Extract the callee identifier via Call.getCalleeIdentifier().
     - If the name is one of: "strcpy", "stpcpy", "strcat" (you can extend the set if needed), proceed; otherwise return.

  b) Obtain and analyze the destination argument:
     - For strcpy/stpcpy/strcat, the destination is argument index 0.
     - Let DestArg = Call.getArgExpr(0).
     - Remove implicit casts by using DestArg->IgnoreImplicit().
     - Find the underlying array entity:
       - First try findSpecificTypeInChildren<DeclRefExpr>(DestArg). If found, try to get the array size via getArraySizeFromExpr(ArraySize, DRE). If this succeeds, we have a fixed-size array.
       - If that fails, try findSpecificTypeInChildren<MemberExpr>(DestArg). If found, inspect the field’s type:
         - Get FieldDecl* FD = cast<FieldDecl>(ME->getMemberDecl()).
         - QualType FT = FD->getType().
         - If const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(FT.getTypePtr()), then record:
           - Capacity = CAT->getSize() (APInt).
           - Element type = CAT->getElementType(). Ensure it is a character type (isAnyCharacterType() or check for char/signed char/unsigned char).
         - If not a ConstantArrayType, return (we only warn when destination is a fixed-size array).
       - If neither DeclRefExpr nor MemberExpr gives a fixed-size array, return.

  c) If destination is a fixed-size char array:
     - Inspect the source argument (argument index 1 for strcpy/stpcpy; for strcat the source is also index 1):
       - Let SrcArg = Call.getArgExpr(1).
       - Try to determine if the source is a string literal using getStringSize(StringSize, SrcArg).
         - If it is a string literal:
           - Compare StringSize (number of characters, not including the terminating null) against Capacity.
           - If StringSize >= Capacity, report a bug (copy will overflow or lacks room for NUL).
           - If StringSize < Capacity, do not report.
         - If it is NOT a string literal:
           - Report a bug because the copy is unbounded and the destination is a fixed-size array; the source’s runtime length can exceed capacity.

  d) Bug reporting:
     - Create a non-fatal error node via generateNonFatalErrorNode().
     - Emit a PathSensitiveBugReport with a short message like:
       - "Unbounded string copy into fixed-size buffer may overflow; use strscpy with sizeof(dest)."
     - Anchor the report to the call expression’s source range.

4. Helpers to implement in the checker (small, local utilities)
- bool isUnboundedStringCopy(const CallEvent &Call):
  - Return true if callee name is one of {"strcpy", "stpcpy", "strcat"}.

- bool getFixedArraySizeFromMemberExpr(const MemberExpr *ME, llvm::APInt &OutSize, QualType &ElemTy):
  - From ME->getMemberDecl()->getType(), dyn_cast to ConstantArrayType and extract size and element type.

- bool getFixedArraySizeFromDestExpr(const Expr *DestArg, llvm::APInt &OutSize, QualType &ElemTy):
  - Try DeclRefExpr path using getArraySizeFromExpr.
  - Else try MemberExpr path using getFixedArraySizeFromMemberExpr.
  - Return true only if a ConstantArrayType of char/signed char/unsigned char is found.

5. Notes and Simplifications
- This checker deliberately does not attempt to prove safety via preceding guards like if (strlen(src) < sizeof(dest)) …; to keep the logic simple and robust, it only:
  - Requires that the destination is a fixed-size char array.
  - Requires that the call is to an unbounded copy API.
  - Optionally suppresses when the source is a string literal that definitely fits (StringSize < Capacity).
- Do not warn for bounded APIs like strscpy/strlcpy/strncpy; this checker only targets unbounded copies as per the target patch.
- The provided utility functions used:
  - findSpecificTypeInChildren to retrieve DeclRefExpr/MemberExpr under DestArg.
  - getArraySizeFromExpr to get array capacity from DeclRefExpr.
  - getStringSize to evaluate string literal lengths.
