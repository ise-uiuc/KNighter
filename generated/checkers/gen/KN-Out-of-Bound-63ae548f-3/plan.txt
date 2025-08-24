Plan

1) Program state
- No custom program state is necessary. We will rely on:
  - The analyzer’s existing constraint manager to reason about the index range.
  - The provided helper inferSymbolMaxVal to query an index’s maximum feasible value.
  - A small amount of local AST inspection to identify the specific LUT arrays and their compile-time size.

2) Helper routines (internal to the checker)
- isTFLutColorArray(const Expr *Base, StringRef &ColorOut, const ConstantArrayType *&ArrTy):
  - Input: the ArraySubscriptExpr base (after IgnoreParenImpCasts()).
  - Return true if Base is a MemberExpr chain of the form “...->tf_pts.red” (or green/blue).
    - Steps:
      - dyn_cast<MemberExpr>(Base) => ME1, ensure its member is a FieldDecl named in {"red","green","blue"}. Save ColorOut.
      - Get ME1->getBase()->IgnoreParenImpCasts() => ME2Expr; dyn_cast<MemberExpr>(ME2Expr) => ME2; ensure ME2 member is a FieldDecl named "tf_pts".
      - For ME1’s FieldDecl FD1, fetch FD1->getType(). dyn_cast<ConstantArrayType> to ArrTy. If not ConstantArrayType, return false (we can’t know the bound reliably).
  - If all checks pass, return true and output ArrTy (contains the constant array bound) and ColorOut.

- getIndexInfo(const Expr *Idx, CheckerContext &C, bool &IsConst, llvm::APSInt &ConstVal, SymbolRef &Sym):
  - Idx = AE->getIdx()->IgnoreParenImpCasts().
  - If EvaluateExprToInt(ConstVal, Idx, C) returns true, set IsConst = true and Sym = nullptr.
  - Else, IsConst = false, try to get the symbol with: Sym = C.getState()->getSVal(Idx, C.getLocationContext()).getAsSymbol(); (if null, we will be conservative).

- guardedByTransferPointsCondition(const Expr *Idx, const Stmt *AccessSite, CheckerContext &C):
  - Best-effort suppression to avoid FPs when there is an obvious nearby guard.
  - Find a nearest enclosing IfStmt or loop condition using findSpecificTypeInParents<IfStmt>(AccessSite, C) (or ForStmt/WhileStmt similarly).
  - If found, take its condition expression CondE and:
    - Extract index name text (use ExprHasName(CondE, "<index-name>", C)).
    - Check also ExprHasName(CondE, "TRANSFER_FUNC_POINTS", C).
    - If both are present, return true (assume guarded). Otherwise false.
  - This function is optional; we will call it only when constraints are inconclusive and we would otherwise warn.

3) Callback selection and implementation details

A) checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const
- Why: This is invoked on loads/stores. The problematic access is a read from output_tf->tf_pts.{red,green,blue}[i], so it naturally passes through here as a load.
- Steps:
  1) Process only loads (IsLoad == true).
  2) Cast S to ArraySubscriptExpr: const auto *AE = dyn_cast_or_null<ArraySubscriptExpr>(S). If not AE, return.
  3) Identify the TF LUT array:
     - Base = AE->getBase()->IgnoreParenImpCasts().
     - Call isTFLutColorArray(Base, ColorName, ArrTy). If false, return (we only flag indexing into tf_pts.{red,green,blue}).
  4) Obtain the array bound:
     - From ArrTy, get size: llvm::APInt ArrSize = ArrTy->getSize(). (Use ArrSize.getLimitedValue() for comparisons.)
  5) Analyze the index:
     - Idx = AE->getIdx()->IgnoreParenImpCasts().
     - Use getIndexInfo(Idx, C, IsConst, ConstVal, Sym).
  6) Decide safety:
     - If IsConst == true:
       - If ConstVal.uge(ArrSize) => definite OOB; report.
       - Else return (safe).
     - Else (symbolic or unknown):
       - If Sym != nullptr:
         - const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C).
         - If MaxV is not null AND MaxV->ult(ArrSize) => proven safe; return.
         - Else (unknown OR MaxV >= ArrSize) => not proven safe; continue to 7).
       - If Sym == nullptr: not proven safe; continue to 7).
  7) Optional guard suppression:
     - If guardedByTransferPointsCondition(Idx, S, C) returns true, return (assume guarded).
  8) Report bug:
     - generateNonFatalErrorNode() and emit a PathSensitiveBugReport with a short message, e.g.:
       - "Possible out-of-bounds read from tf_pts.[red|green|blue]; missing index < TRANSFER_FUNC_POINTS check."
     - Optionally include a note with the array bound and the index expression textual dump for clarity.

B) No other callbacks are strictly necessary
- We do not need checkBranchCondition or a custom program state map because:
  - The constraint manager and inferSymbolMaxVal suffice to conclude when an index is definitely within bounds.
  - The optional guard detection step uses findSpecificTypeInParents and ExprHasName to avoid FPs without maintaining state.

4) Bug reporting details
- Create a checker-local BugType, e.g., BugType BT("Transfer-function LUT index OOB", "API Misuse").
- Use std::make_unique<PathSensitiveBugReport>(BT, Msg, Node).
- Keep the message short and clear, per instruction.

5) Notes and tuning
- We only analyze subscript expressions where the array is a field named in {"red","green","blue"} coming from a parent field named "tf_pts"; this makes the checker targeted and reduces false positives.
- We rely on the array field’s ConstantArrayType to get the true bound (which is the macro TRANSFER_FUNC_POINTS after preprocessing), so we do not need to evaluate the macro explicitly.
- If needed, we can expand the checker in the future to track additional LUTs or allow a configurable whitelist of field names.
