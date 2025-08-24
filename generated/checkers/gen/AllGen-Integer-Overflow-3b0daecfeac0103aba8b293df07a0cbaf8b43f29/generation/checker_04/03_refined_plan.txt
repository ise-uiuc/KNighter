1) Program state
- No custom program state is needed. The detection can be done purely at call sites.

2) Callbacks and implementation

- checkPreCall (core detection)
  - Goal: Flag calls to kmalloc/kzalloc-family that pass a size argument computed by multiplication (count * element_size), which is overflow-prone, and recommend using kcalloc/kvcalloc.
  - Steps:
    1) Identify target allocators:
       - Obtain callee name via Call.getCalleeIdentifier()->getName().
       - Match against:
         - kmalloc, kzalloc
         - kmalloc_node, kzalloc_node
         - (Do not warn for kcalloc/kvcalloc/…_array variants; those are already overflow-safe.)
    2) Extract the size argument:
       - For kmalloc/kzalloc and their _node variants, the first argument is the size expression: const Expr *SizeArg = Call.getArgExpr(0).
       - If SizeArg is null, return.
    3) Find a multiplication in SizeArg:
       - Use findSpecificTypeInChildren<BinaryOperator>(SizeArg) and check op == BO_Mul.
       - If not a multiplication, do nothing.
    4) Ensure one operand is a sizeof(...) expression:
       - Within the found BinaryOperator MulBO, locate a UnaryExprOrTypeTraitExpr with kind UETT_SizeOf using findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(MulBO).
       - If no sizeof(...) found, return (to reduce false positives).
       - Determine operands:
         - Let L = MulBO->getLHS()->IgnoreParenImpCasts()
         - Let R = MulBO->getRHS()->IgnoreParenImpCasts()
         - If sizeof is found within L but not R, set ElementSizeExpr = L, CountExpr = R; if in R but not L, swap.
         - If sizeof is found in both or neither side clearly, return (be conservative).
    5) Filter out trivial constants:
       - If EvaluateExprToInt returns true for CountExpr, it’s a compile-time constant. Skip to avoid noisy reports on fixed-size allocations.
       - If EvaluateExprToInt on the entire SizeArg succeeds, skip (fully constant size).
    6) Optional suppression using symbolic upper bound (if easy to compute):
       - Try to get a symbolic value for CountExpr: SVal SV = C.getSVal(CountExpr); SymbolRef Sym = SV.getAsSymbol();
       - If Sym exists:
         - Retrieve max bound: const llvm::APSInt *MaxCount = inferSymbolMaxVal(Sym, C);
         - Get element size as integer: llvm::APSInt ElemSize; EvaluateExprToInt(ElemSize, ElementSizeExpr, C).
         - Compute size type width: unsigned W = C.getASTContext().getTypeSize(Call.getArgExpr(0)->getType());
         - Construct SIZE_MAX: llvm::APSInt SizeMax(W, /*Unsigned*/true); SizeMax.setAllBits();
         - Compute Bound = SizeMax / ElemSize; if MaxCount exists and *MaxCount <= Bound, skip warning.
       - If any of these steps fail, proceed with warning (fail-open).
    7) Emit report:
       - Create a non-fatal error node: ExplodedNode *N = C.generateNonFatalErrorNode();
       - Message: "kmalloc/kzalloc with size as count*element_size; use kcalloc/kvcalloc to avoid overflow."
       - Use the multiplication operator (MulBO) or SizeArg as the report location.
       - Emit: C.emitReport(std::make_unique<PathSensitiveBugReport>(...)).

- No other callbacks are required.

3) Helper routines (internal to the checker)
- bool isOverflowProneAllocator(const CallEvent &Call):
  - Returns true if callee is one of {kmalloc, kzalloc, kmalloc_node, kzalloc_node}.
- bool isAlreadyOverflowCheckedAllocator(const CallEvent &Call):
  - Returns true if callee is one of {kcalloc, kvcalloc, kmalloc_array, kcalloc_node, kvcalloc_node}.
- bool findMulAndSplit(const Expr *SizeArg, const BinaryOperator *&MulBO, const Expr *&ElementSizeExpr, const Expr *&CountExpr, CheckerContext &C):
  - Finds a BO_Mul and identifies which side is sizeof(...) and which is the count, as described above.
- bool isConstExpr(const Expr *E, CheckerContext &C):
  - Wrapper using EvaluateExprToInt.

4) Reporting
- Use a single, concise message:
  - "Use kcalloc/kvcalloc(count, size) instead of kmalloc/kzalloc(count*size); multiplication may overflow."
- Point to the multiplication site if possible for clarity.

5) Notes and false-positive control
- Requiring a sizeof(...) in one operand and rejecting compile-time-constant CountExpr significantly reduces noise.
- Optional: If you successfully infer a tight max bound for the count (inferSymbolMaxVal) that proves no overflow is possible for the given element size, suppress the warning.
- Do not warn for calls already using kcalloc/kvcalloc or *_array helpers.
