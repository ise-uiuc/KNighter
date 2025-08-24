Plan: Detect narrow or mixed-width multiplication whose result is later widened when assigned/added to a wider integer (e.g., u64/dma_addr_t), potentially overflowing before widening.

1) No custom program state
- Do not register any ProgramState traits or maps. This checker is purely syntactic/type-based and path-insensitive for this pattern.

2) Chosen callbacks
- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
  Purpose: Catch assignments and compound assignments when a value is bound to a location. Inspect the LHS type (target) and the RHS expression to see if the RHS contains a multiplication performed in a narrower type than the target type.
- checkPostStmt(const DeclStmt *DS, CheckerContext &C) const
  Purpose: Catch variable initializations that assign a multiplication result into a wide integer (e.g., u64, dma_addr_t).

3) Shared helpers (internal to the checker)
- getTypeBitWidth(QualType QT, CheckerContext &C):
  - Return C.getASTContext().getTypeSize(QT) in bits.
- isIntegerLike(QualType QT):
  - Return true if QT is an integer type or an enum type (IgnoreParens/Typedefs/Qualifiers).
- isWideTargetType(QualType QT, CheckerContext &C):
  - Return true if isIntegerLike(QT) and getTypeBitWidth(QT, C) >= 64.
  - Also allow typedef-name checks: if QT is a TypedefType whose decl name equals "dma_addr_t", still use bit width; only report when width >= 64 (avoids false positives on 32-bit builds).
- findFirstSuspiciousMul(const Expr *E, unsigned TargetBits, const BinaryOperator *&OutMul, CheckerContext &C):
  - Recursively traverse E (ignore parens and implicit casts).
  - If node is BinaryOperator with opcode BO_Mul:
    - Let MulBits = getTypeBitWidth(MulExpr->getType(), C).
    - If MulBits < TargetBits, record this BinaryOperator in OutMul and stop.
  - Otherwise, recurse into child expressions until a match is found or tree ends.
  - This flags cases like:
    - size64 = pitch32 * height32;
    - addr64 += (src_x >> 16) * cpp8/32;
    - addr64 += pitch32 * yoff32;
    - addr64 = addr64 + (pitch32 * yoff32) + ...;
- isConstantFolded(const Expr *E, CheckerContext &C):
  - Try EvaluateExprToInt(APSInt, E, C); return true if evaluation succeeds.
  - If the multiplication expression is a fully constant expression (no runtime multiplication), skip reporting to reduce noise.
- emitReport(const BinaryOperator *MulBO, QualType LHSType, CheckerContext &C):
  - Create or reuse a BugType like "Mixed-width multiplication overflow".
  - Use generateNonFatalErrorNode and emit a PathSensitiveBugReport at MulBO->getOperatorLoc().
  - Message: "Multiplication occurs in narrower type then widened; possible overflow before assignment/addition to wide type."
  - Optionally include a short note: "Cast an operand to 64-bit or use a wide accumulator before multiply."

4) checkBind implementation
- From S, find the syntactic context using parents:
  - Try findSpecificTypeInParents<BinaryOperator>(S, C) to capture simple assignment (=).
  - Try findSpecificTypeInParents<CompoundAssignOperator>(S, C) for +=, -=, etc.
  - If neither found, return.
- For BinaryOperator (simple assignment):
  - If not BO_Assign, return.
  - Get LHS = BO->getLHS()->IgnoreParenImpCasts(), RHS = BO->getRHS().
  - Get LHSType = LHS->getType(). If !isWideTargetType(LHSType, C), return.
  - Search RHS for suspicious multiply:
    - const BinaryOperator *MulBO = nullptr;
    - findFirstSuspiciousMul(RHS, getTypeBitWidth(LHSType, C), MulBO, C).
    - If no MulBO, return.
    - If isConstantFolded(MulBO, C), return.
    - Otherwise, emitReport(MulBO, LHSType, C).
- For CompoundAssignOperator (e.g., +=):
  - If the operator is not one of BO_AddAssign or BO_SubAssign, return. (We care about adding/subtracting a product into wide accumulator; for BO_MulAssign, the calculation already uses LHS' type, so it’s generally safe.)
  - Get LHS = CAO->getLHS()->IgnoreParenImpCasts(), RHS = CAO->getRHS().
  - If !isWideTargetType(LHSType, C), return.
  - Search RHS for suspicious multiply (same as above).
  - If found and not constant-folded, emit report.

5) checkPostStmt(DeclStmt) implementation
- For each VarDecl in DS:
  - If it has no initializer, continue.
  - Let QT = VD->getType(); if !isWideTargetType(QT, C), continue.
  - Let Init = VD->getInit(); search for suspicious multiply:
    - const BinaryOperator *MulBO = nullptr;
    - findFirstSuspiciousMul(Init, getTypeBitWidth(QT, C), MulBO, C).
  - If found and not constant-folded, emit report.

6) What this catches (examples aligned with the patch)
- args->size = args->pitch * args->height; where size is u64 and pitch/height are 32-bit.
- addr += (new_state->src.x1 >> 16) * fb->format->cpp[0]; where addr is dma_addr_t (64-bit) and operands are 32-bit or smaller.
- addr += pitch * y_offset_in_blocks; where addr is 64-bit and both operands are 32-bit.
- Also handles longer chains where a multiplication subexpression is part of a larger RHS used in assignment/addition to a wide integer.

7) What is considered safe (no report)
- Either operand of the multiplication is explicitly widened (e.g., (u64)pitch * height), because the result type of '*' becomes >= target width; getTypeBitWidth(MulExpr) >= TargetBits.
- The multiplication is fully constant-evaluable (optional suppression via isConstantFolded).
- LHS target type < 64 bits (no widening risk).
- Compound multiply-assign like u64_acc *= u32_x; (computation is done in LHS’ wide type).

8) Notes to keep implementation simple and precise
- Use getTypeSize in bits to compare operand/result vs target widths; avoid architecture assumptions.
- Rely on the result type of the '*' BinaryOperator: if it’s already >= target width, don’t warn (covers correct fixes via explicit casts/wide accumulators).
- Deduplication is typically not necessary; the AST node for '*' is unique at a location. If needed, key by SourceLocation of '*'.

This minimal two-callback approach (checkBind and checkPostStmt) is sufficient to detect the mixed-width multiplication overflow pattern described in the target patch.
