1) Program state
- No custom program state is necessary. This checker is a local, call-site based check.

2) Callback functions and implementation steps

A. checkPreCall (core callback; single-pass detection)
- Goal: Catch unbounded string copies where destination is a fixed-size buffer and source may be longer than destination.

- Identify target calls:
  - Retrieve callee identifier with Call.getCalleeIdentifier().
  - If the name equals "strcpy", proceed. Otherwise, return.

- Extract arguments:
  - const Expr *DstArg = Call.getArgExpr(0);
  - const Expr *SrcArg = Call.getArgExpr(1);

- Determine destination fixed-size:
  - Implement a small helper getConstArraySize(Size, DstArg, C):
    - E = DstArg->IgnoreParenImpCasts().
    - First try the provided getArraySizeFromExpr(Size, E).
    - If that fails and E is a MemberExpr:
      - Get the FieldDecl via cast<FieldDecl>(ME->getMemberDecl()).
      - Get the field’s QualType QT = FD->getType().
      - If QT is ConstantArrayType, extract its Size = CAT->getSize().
      - Return true on success.
    - If the destination is an array (DeclRefExpr to array variable or MemberExpr of array field), this returns true and Size is the compile-time bound.
    - If this helper fails (i.e., destination isn't a known fixed-size array), return from the checker without warning (to avoid FPs on unknown pointers).

- Evaluate source length and decide report kind:
  - Attempt to get a precise size if it’s a string literal:
    - Use provided getStringSize(SrcLen, SrcArg) on SrcArg->IgnoreImpCasts().
    - If true:
      - Remember: getStringSize returns number of characters without the null terminator.
      - If SrcLen.uge(DstSize): definite overflow (since we need at least SrcLen+1 bytes in dest).
        - Report: "strcpy into fixed-size buffer overflows; use strscpy(dest, src, sizeof(dest))."
      - Else: do nothing (provably safe).
  - If not string literal:
    - Optionally try to detect an obvious bounded source array:
      - If getConstArraySize(SrcBound, SrcArg, C) succeeds:
        - We still cannot prove the runtime string is shorter than DstSize; be conservative.
        - If SrcBound.uge(DstSize): report as "possible overflow".
        - Else: still "possible overflow" because strcpy is unbounded (keeps FPs low-level but aligned with "possible overflow").
    - Otherwise (unknown source size):
      - Report as "Possible buffer overflow: strcpy into fixed-size buffer; use strscpy(dest, src, sizeof(dest))."

- Bug report emission:
  - Create a BugType (category: "Security", name: "Unbounded string copy into fixed-size buffer").
  - Use generateNonFatalErrorNode to create a node.
  - Create a PathSensitiveBugReport with a short, clear message:
    - Definite: "strcpy overflows fixed-size buffer (dest size N, source literal length M)."
    - Possible: "Possible overflow: strcpy into fixed-size buffer; use strscpy(dest, src, sizeof(dest))."
  - Add a source range on the call expression or specifically the destination argument for clarity.
  - Emit the report.

B. (Optional) Helper utilities to include in the checker
- getConstArraySize(llvm::APInt &Size, const Expr *E, CheckerContext &C):
  - As described above, try:
    - getArraySizeFromExpr(Size, E->IgnoreParenImpCasts()).
    - If MemberExpr: extract FieldDecl->getType(); if ConstantArrayType, set Size.
  - Return bool success.
- isStrcpy(const CallEvent &Call):
  - Return true if Call.getCalleeIdentifier() and name == "strcpy".

Notes and rationale
- This checker purposely restricts diagnostics to cases where the destination is a compile-time fixed-size array, which aligns with the target bug pattern (e.g., struct field like name[8]).
- It prefers precision when the source is a string literal; otherwise it reports as "possible overflow," which matches the kernel change’s reasoning and recommended fix to strscpy with sizeof(dest).
- No alias tracking or state is used to keep implementation simple and robust.
- We avoid warning when destination size is unknown (e.g., arbitrary char*), reducing false positives.
