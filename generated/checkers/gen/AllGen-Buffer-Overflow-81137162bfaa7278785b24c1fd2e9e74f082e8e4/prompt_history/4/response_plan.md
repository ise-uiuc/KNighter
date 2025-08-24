1) Program State
- No custom program state is necessary. The pattern is detected locally at the call site of strcpy.

2) Callback Functions and Implementation Details

- checkPreCall(const CallEvent &Call, CheckerContext &C) const
  Goal: Detect unbounded strcpy into a fixed-size buffer (especially struct fields).
  Steps:
  1. Identify strcpy:
     - Get callee identifier via Call.getCalleeIdentifier().
     - If null or name != "strcpy", return.

  2. Extract arguments:
     - DestE = Call.getArgExpr(0)
     - SrcE  = Call.getArgExpr(1)

  3. Determine destination buffer as a fixed-size array:
     - Remove implicit casts from DestE: E0 = DestE->IgnoreImpCasts().
     - Try to find an underlying DeclRefExpr or MemberExpr:
       - Prefer using findSpecificTypeInChildren<DeclRefExpr>(DestE) and if not found, findSpecificTypeInChildren<MemberExpr>(DestE). If these return null, also try E0 directly if it is DeclRefExpr or MemberExpr.
     - If DeclRefExpr:
       - Use provided getArraySizeFromExpr(ArraySize, FoundDeclRefExpr).
     - If MemberExpr:
       - Retrieve the FieldDecl: auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()).
       - From FD->getType(), if it’s ConstantArrayType (const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(FD->getType().getTypePtr())), obtain its size (CAT->getSize()).
     - If destination is not identified as a ConstantArrayType with a known bound, return (we only warn when a fixed-size destination is known).

  4. Evaluate source size if possible:
     - Remove implicit casts from SrcE: E1 = SrcE->IgnoreImpCasts().
     - If E1 is StringLiteral, use provided getStringSize(StringSize, E1). If true:
       - If StringSize >= DestArraySize, report a definite overflow (see reporting below).
       - Else (StringSize < DestArraySize), do not report (safe case).
     - Else (source is not a string literal):
       - Optionally try to detect if source is a fixed-size array too:
         - Look for DeclRefExpr or MemberExpr in the source via findSpecificTypeInChildren.
         - If found and it resolves to ConstantArrayType with size S, and S >= DestArraySize, report as a likely overflow.
       - If no reliable upper bound for source can be determined, report a potential overflow because strcpy is unbounded and destination has a fixed size.

  5. Bug reporting:
     - Create a non-fatal error node via generateNonFatalErrorNode() and bail out if null.
     - Message should be short and clear:
       - For definite overflow (string literal too long): "strcpy overflows fixed-size buffer."
       - For potential overflow (variable-length source): "Unbounded strcpy into fixed-size buffer may overflow."
     - If the destination is a struct field (MemberExpr with FieldDecl), include the field name in the message when available (e.g., "… into field 'name'").
     - Use std::make_unique<PathSensitiveBugReport>(BugType, Message, ErrorNode) and C.emitReport(std::move(R)).

3) Helper Logic (inside the checker; no program state)
- getFixedArraySizeFromDestArg(const Expr *DestE, CheckerContext &C, llvm::APInt &OutSize):
  - Try DeclRefExpr path first using getArraySizeFromExpr(OutSize, DRE).
  - Try MemberExpr path by inspecting FieldDecl->getType() as ConstantArrayType.
  - If both fail, return false.
- getSourceStringLiteralSize(const Expr *SrcE, CheckerContext &C, llvm::APInt &OutSize):
  - Use provided getStringSize(OutSize, SrcE->IgnoreImpCasts()).

4) Notes and Reasoning
- We focus on strcpy since it is unbounded; strscpy/strlcpy are safe alternatives that require an explicit bound. The fix in the patch uses strscpy with sizeof(dest).
- We only warn when the destination size is known and fixed (ConstantArrayType). This targets exactly the risky pattern (copying into a fixed-size array field like name[8]).
- We avoid tracking aliases or path conditions; no state maps are needed.
- We use the supplied utilities:
  - findSpecificTypeInChildren to recover DeclRefExpr/MemberExpr under implicit decay/casts.
  - getArraySizeFromExpr for DeclRefExpr destinations.
  - getStringSize for source literals.
- Reporting is concise, as requested.
