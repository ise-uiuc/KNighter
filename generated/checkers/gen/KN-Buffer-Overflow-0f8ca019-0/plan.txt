1) Program state
- No custom program state is needed. This checker is a local, AST-based pattern detector.

2) Callbacks and implementation steps

Step A. Hook array subscripts
- Callback: checkPostStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const
- Goal: When an array is indexed by a loop induction variable whose loop bound comes from one macro/constant, verify that the array’s compile-time size is not smaller than the loop’s upper bound (considering the comparison operator). If smaller, report potential out-of-bounds.

Implementation details:
1) Retrieve the nearest enclosing ForStmt
   - Use findSpecificTypeInParents<ForStmt>(ASE, C). If none, return.

2) Extract loop induction variable and its initial value
   - From ForStmt->getInit():
     - Case 1: DeclStmt with a single VarDecl having an initializer. Save VarDecl* as LoopVar. Evaluate initializer to int with EvaluateExprToInt; require it to be 0; otherwise return.
     - Case 2: BinaryOperator “i = 0”. The LHS must be DeclRefExpr to a VarDecl (LoopVar). Evaluate RHS with EvaluateExprToInt; require it to be 0; otherwise return.
   - Keep it simple: only handle the common “i = 0” initialization.

3) Check increment is +1
   - From ForStmt->getInc():
     - Accept UnaryOperator ++i or i++ on the same LoopVar.
     - Accept “i += 1” (BinaryOperator with opcode BO_AddAssign and RHS == 1).
   - If not matched, return.

4) Extract the loop upper bound and the comparison operator
   - From ForStmt->getCond():
     - Expect BinaryOperator with opcode BO_LT or BO_LE.
     - LHS must be DeclRefExpr to the same LoopVar.
     - Evaluate RHS to integer bound N via EvaluateExprToInt. If fails, return.
   - Compute the exclusive bound BoundExcl:
     - If op is ‘<’, BoundExcl = N.
     - If op is ‘<=’, BoundExcl = N + 1.

5) Ensure the index expression is exactly the loop variable
   - From ASE->getIdx()->IgnoreParenImpCasts():
     - Must be a DeclRefExpr that resolves to the same LoopVar. If not, return.
   - Keep it simple: only flag when the index is the loop variable directly (no offsets or complex expressions).

6) Retrieve the compile-time array size of the subscripted array
   - We must get the ConstantArrayType of the array being subscripted.
   - From ASE->getBase()->IgnoreParenImpCasts():
     - If it is a MemberExpr:
       - Get FieldDecl* via getMemberDecl().
       - Get the field’s QualType QT = FD->getType().
       - Try dyn_cast<ConstantArrayType>(QT.getTypePtr()). If not array type, return.
       - Let ArraySize = CAT->getSize().getZExtValue().
     - Else if it is a DeclRefExpr:
       - Use provided getArraySizeFromExpr(ArraySizeAPInt, DeclRefExpr). If success, ArraySize = ArraySizeAPInt.getZExtValue().
     - Otherwise return (we only handle known constant-sized arrays).

7) Compare loop bound and array size
   - If BoundExcl > ArraySize, then the loop can index the array out-of-bounds (max index equals BoundExcl-1, so BoundExcl > ArraySize implies (BoundExcl-1) >= ArraySize).
   - If this holds, report a bug.

8) Emit bug report
   - Create a non-fatal error node (C.generateNonFatalErrorNode()).
   - Emit a short message: “Loop bound exceeds target array size; possible out-of-bounds index.”
   - Attach the range at ASE->getExprLoc().
   - Use std::make_unique<PathSensitiveBugReport> with a checker-owned BugType.

Notes:
- This checker intentionally focuses on the common and simple pattern:
  - for (int i = 0; i < CONST; i++) arr[i] = ...
  - Array is a field or variable with compile-time constant bound.
- We do not attempt to model data-dependent bounds or complex index expressions.
- We do not attempt to prove guarding if-statements dominate the access; to keep the checker simple, it flags when the loop’s exclusive bound is greater than the array’s size.

Step B. Optional false-positive reduction (simple guard recognition)
- Not required, but if desired and simple, before reporting:
  - Search upwards with findSpecificTypeInParents<const IfStmt>(ASE, C) to see if the nearest guarding condition is of the form (i < K) or (i >= K) with K <= ArraySize and that ASE is syntactically within the guarded “then” that enforces i < K.
  - If detected and trivially safe, suppress. Otherwise keep the report.
- Prefer skipping this to keep implementation minimal, as suggested.

3) Utility functions used
- findSpecificTypeInParents<T>(...) to locate the enclosing ForStmt (and optional enclosing IfStmt if implementing the optional reduction).
- EvaluateExprToInt(...) to extract numeric values for loop initializer, bound, and increments where applicable.
- getArraySizeFromExpr(...) only for DeclRefExpr bases; for struct fields use FieldDecl type and ConstantArrayType directly.

4) Summary of minimal conditions to warn
- Inside a ForStmt:
  - init: i = 0 (or int i = 0)
  - cond: i < N or i <= N where N is compile-time int
  - inc: ++i, i++, or i += 1
- The ArraySubscriptExpr index is i (exactly).
- The subscripted array has compile-time constant size A (from ConstantArrayType).
- BoundExcl > A (i.e., (i runs 0..BoundExcl-1) may reach index >= A).
- Emit: “Loop bound exceeds target array size; possible out-of-bounds index.”
