1) Program state
- No custom program states are necessary. We will rely on:
  - Existing path constraints (and inferSymbolMaxVal) to learn index bounds.
  - Local AST/CFG inspection to determine the array bound and whether an explicit guard exists.

2) Callbacks and steps

Step A. checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C)
Goal: Flag array subscripts that index a fixed-size LUT with an index that may exceed the bound and is not explicitly guarded.

Implementation details:
- Identify the array access:
  - From S, obtain the ArraySubscriptExpr (ASE). If S is not an ASE, try findSpecificTypeInChildren<ArraySubscriptExpr>(S). If none, return.
- Extract the array bound (N):
  - Let BaseE = ASE->getBase()->IgnoreParenImpCasts().
  - Try to get the array size N as follows:
    - If BaseE is DeclRefExpr with ConstantArrayType, use the provided getArraySizeFromExpr to fetch the size into APInt N.
    - Else if BaseE is a MemberExpr (e.g., output_tf->tf_pts.red), inspect the referred declaration’s type:
      - FieldDecl FD = cast<FieldDecl>(ME->getMemberDecl()).
      - If FD->getType() is ConstantArrayType, extract size (FD->getType()->getAs<ConstantArrayType>()->getSize()) into APInt N.
    - If we still cannot obtain a constant array bound, bail (return).
  - Note: We don’t need the element region. We only care about array bound N.
- Extract the index:
  - Let IdxE = ASE->getIdx()->IgnoreParenImpCasts().
  - First, try to evaluate the index to a constant using EvaluateExprToInt(APSInt IdxConst, IdxE, C):
    - If evaluable and IdxConst >= N, report (go to Step C).
    - If evaluable and IdxConst < N, consider safe; return.
  - Otherwise, get the index symbol:
    - SymbolRef IdxSym = C.getSVal(IdxE).getAsSymbol();
    - If no symbol is available, give up (avoid FP); return.
- Use constraints to bound the index symbol:
  - Query maximum value using inferSymbolMaxVal(IdxSym, C):
    - If maxVal exists:
      - If maxVal >= N (i.e., analyzer cannot prove Idx < N), continue to Step B (syntactic guard check). We will only report if there is no known syntactic guard.
      - Else (maxVal < N), safe; return.
    - If maxVal does not exist (unknown), continue to Step B (syntactic guard check). We will only report without a guard if max is unknown and we cannot find a proper guard.
- Step B. Check for an explicit syntactic guard tied to the same index:
  - Attempt to locate a surrounding loop or branch that provides a bound on Idx:
    - Find enclosing ForStmt or WhileStmt via findSpecificTypeInParents<ForStmt>(S) / findSpecificTypeInParents<WhileStmt>(S). If found:
      - For ForStmt: analyze its condition expression CondE (if any). If CondE is a BinaryOperator that compares the same index variable with a constant bound C:
        - Accepted safe forms: (Idx < C), (Idx <= C-1), (C > Idx), (C-1 >= Idx). Use EvaluateExprToInt on the constant side(s) to derive a strict upper bound. If strict upper bound <= N, treat as guarded; return.
      - For WhileStmt: similar analysis on its condition.
    - If an IfStmt guard syntactically guarding the index is present just above this access (e.g., if (Idx >= N) return/break;), CSA path constraints will already have set bounds in the current path; inferSymbolMaxVal would be < N. Hence additional IfStmt scanning is optional. If desired, you can scan immediate parent IfStmt and check for comparisons with N, but this is not necessary if the earlier constraint step is used.
  - If no syntactic guard is found (and either maxVal >= N or maxVal is unknown), proceed to report.
- Step C. Report:
  - Create a non-fatal error node with generateNonFatalErrorNode().
  - Emit a concise report using std::make_unique<PathSensitiveBugReport>:
    - Checker name: e.g., “LUTIndexBoundsChecker”.
    - Message: “Possible out-of-bounds LUT index; missing ‘i < array_size’ check.”
  - Attach the ASE->getIdx() as the interesting location so the path highlights the index expression.
  - Note: This code typically accesses 3 channels (red/green/blue). To limit duplicates, only report when the base MemberExpr name is “red” (or report all if desired). Implement this minor filter by inspecting MemberExpr’s field name.

3) Helper logic (internal helpers you will write)
- getArrayBoundFromBaseExpr(const Expr *BaseE, llvm::APInt &N):
  - If DeclRefExpr, use getArraySizeFromExpr(N, BaseE).
  - If MemberExpr, fetch FieldDecl then inspect its QualType for ConstantArrayType and return N.
- sameIndexSymbol(const Expr *IdxE, const Expr *OtherIdxE, CheckerContext &C):
  - To compare if a loop condition uses the same index variable, extract SymbolRef via C.getSVal(… ).getAsSymbol() from both expressions and compare pointer equality.
- extractStrictUpperBoundFromCond(const Expr *CondE, SymbolRef IdxSym, llvm::APSInt &StrictUB, CheckerContext &C):
  - If CondE is BinaryOperator comparing IdxSym with a constant C, compute StrictUB:
    - For “Idx < C” or “C > Idx”: StrictUB = C.
    - For “Idx <= C” or “C >= Idx”: StrictUB = C + 1.
    - For “Idx < C-1” or similar simple arithmetic on the constant side, try EvaluateExprToInt on RHS.
  - Return true if parsed; otherwise false.

4) Why this catches the target bug
- The buggy code computes i from region/segment math and doesn’t guard it against TRANSFER_FUNC_POINTS before indexing output_tf->tf_pts.{red,green,blue}[i].
- In the loop, the analyzer will know i < start_index + NUMBER_SW_SEGMENTS. Since start_index is computed and may exceed array size, inferSymbolMaxVal(i) will be >= N. Since no explicit “i < N” guard exists, the checker reports.
- After the patch, the explicit guard “if (i >= TRANSFER_FUNC_POINTS) return false;” creates a path constraint i < N for the access, making inferSymbolMaxVal < N and thus silencing the warning.

5) Notes to keep it simple and precise
- No custom maps or traits; let the analyzer’s constraint manager provide max bounds.
- Only warn when:
  - Index is constant and out-of-bounds; or
  - Symbolic index’s max bound is >= array size and there is no syntactic guard tied to that array size.
- Keep the message short and clear.
