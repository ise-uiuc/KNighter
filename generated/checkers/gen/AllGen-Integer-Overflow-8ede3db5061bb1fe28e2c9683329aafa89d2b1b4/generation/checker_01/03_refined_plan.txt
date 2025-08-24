Plan to detect lossy casts in check_add_overflow calls

1. Program state
- No custom program state is needed. This checker is purely syntactic/semantic on calls. Do not register any ProgramState maps or traits.

2. Callback selection
- Use checkPreCall only.
  - We only need to inspect the call expression’s callee name and argument ASTs and report immediately if we find the pattern.
- No other callbacks are required.

3. Call identification (checkPreCall)
- Retrieve the callee identifier: if none, return.
- Match the function name against:
  - "check_add_overflow"
  - or contains "add_overflow" to catch the builtin "__builtin_add_overflow" invoked through the kernel macro.
- If not matched, return.
- Retrieve the three arguments: A = arg0, B = arg1, C = arg2. If the number of arguments is not 3, return.

4. Extract destination type (for context; no direct reporting basis)
- From C (arg2), try to get the pointee type:
  - If arg2 is a UnaryOperator with opcode UO_AddrOf on a DeclRefExpr, get the VarDecl’s type (pointee type Tdest).
  - If it’s an arbitrary expression, attempt to get the SVal’s region with getMemRegionFromExpr and infer the pointee QualType; if unavailable, skip Tdest-based checks.
- We will NOT report based solely on Tdest being “int” to avoid false positives (the target patch still uses ‘int hdr’). This info is only used as context.

5. Detect lossy explicit casts on operands A/B
Implement a helper isExplicitNarrowingCastOfSizeRelated(const Expr *E, ASTContext &ACtx):
- Goal: return true if E contains an explicit cast (top-level) that converts a size-related value (size_t or sizeof) to a signed narrower (or equal-width signed from unsigned) integer type (commonly int).
- Steps:
  - Let Top = E->IgnoreParens() (do NOT ignore explicit casts).
  - If Top is not a CStyleCastExpr/CXXFunctionalCastExpr/CXXStaticCastExpr, return false.
  - Let ToT = Top->getType().getCanonicalType(); let Sub = castExpr->getSubExpr()->IgnoreParens(); let FromT = Sub->getType().getCanonicalType().
  - Check that ToT is an integer type. If not, return false.
  - Determine if Sub is “size-related”:
    - Sub is a UnaryExprOrTypeTraitExpr of kind UETT_SizeOf.
    - OR FromT == ACtx.getSizeType() (canonical type comparison).
  - If not size-related, return false.
  - Compute bit widths and signedness:
    - unsigned FromIsUnsigned = FromT->isUnsignedIntegerType();
    - unsigned ToIsSigned = ToT->isSignedIntegerType();
    - unsigned FromBits = ACtx.getTypeSize(FromT);
    - unsigned ToBits = ACtx.getTypeSize(ToT).
  - Consider it a problematic narrowing if any of:
    - ToBits < FromBits (truncation), regardless of signedness.
    - ToBits == FromBits and FromIsUnsigned and ToIsSigned (unsigned-to-signed same-width, can flip to negative).
- Return true if problematic narrowing; otherwise false.

6. Apply detection on both operands and report
- In checkPreCall, evaluate:
  - BadA = isExplicitNarrowingCastOfSizeRelated(Call.getArgExpr(0), ACtx)
  - BadB = isExplicitNarrowingCastOfSizeRelated(Call.getArgExpr(1), ACtx)
- If BadA || BadB:
  - Create a non-fatal error node via generateNonFatalErrorNode.
  - Emit a PathSensitiveBugReport with a short message:
    - “Lossy cast to int in check_add_overflow may hide overflow; avoid casting sizeof/size_t to int.”
  - Add a note range at the casted argument expression for better pinpointing.

7. Heuristics and false-positive control
- Only report when there is an explicit narrowing cast on A or B from size-related type to a signed narrower or equal-width-signed type. This matches the target patch (casts removed) and avoids flagging uses where only the destination is ‘int’.
- Do NOT report when there are no explicit casts on A/B, even if the destination result variable is of narrower type (to avoid false positives on existing kernel idioms like ‘int hdr’).

8. Utility usage
- getMemRegionFromExpr: optional, if trying to refine destination type provenance; not required for reporting.
- ExprHasName: not required; we rely on AST kinds to detect sizeof and types.
- findSpecificTypeInParents/Children: not required.

9. Summary of minimal implementation steps
- No program state.
- Implement checkPreCall:
  - Match callee name: "check_add_overflow" or contains "add_overflow".
  - For arg0/arg1, detect explicit narrowing cast from size-related type using isExplicitNarrowingCastOfSizeRelated.
  - If found, report a bug with a short, clear message at the cast location.
