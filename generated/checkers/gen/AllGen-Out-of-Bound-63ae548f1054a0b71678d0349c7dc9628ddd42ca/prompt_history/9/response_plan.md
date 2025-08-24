Plan

1) Program state customization
- No custom program state is required. We will rely on:
  - The constraint manager (via inferSymbolMaxVal) to know the maximum feasible value for the index symbol on the current path.
  - Direct AST inspection and simple source-text checks (ExprHasName) to recognize the specific LUT base expression and the index variable.

2) Callbacks and implementation details

A) checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) — core detection
- Goal: Detect reads/writes to output_tf->tf_pts.{red,green,blue}[i] where i may exceed the LUT bound TRANSFER_FUNC_POINTS (the declared constant length of those arrays).

- Steps:
  1. Filter to array subscripts:
     - dyn_cast the incoming Stmt S to ArraySubscriptExpr (ASE). If not ASE, return.
  2. Match the specific transfer-function LUT base:
     - Let BaseE = ASE->getBase()->IgnoreParenImpCasts().
     - Heuristic match (simple and robust in this driver code):
       - Use ExprHasName(BaseE, "output_tf") AND ExprHasName(BaseE, "tf_pts") AND one of ExprHasName(BaseE, "red")/("green")/("blue").
       - If not all conditions hold, return.
     - Note: This tightly focuses the checker to the exact bug pattern and minimizes false positives.
  3. Require the index to be the loop variable i:
     - Let IdxE = ASE->getIdx()->IgnoreParenImpCasts().
     - If !ExprHasName(IdxE, "i"), return. This avoids flagging the separate “last point” access via start_index.
  4. Retrieve the array bound (TRANSFER_FUNC_POINTS) from the field type:
     - Recover the MemberExpr for the color channel:
       - The ASE base typically is an ArrayToPointerDecay on a MemberExpr of the field red/green/blue. If BaseE is not directly a MemberExpr, call findSpecificTypeInChildren<MemberExpr>(ASE->getBase()) to get the underlying MemberExpr ColorME whose member is one of red/green/blue.
     - From ColorME:
       - auto *FD = dyn_cast<FieldDecl>(ColorME->getMemberDecl()).
       - QualType FT = FD->getType().
       - If const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(FT.getTypePtr()):
         - ArraySize = CAT->getSize() (llvm::APInt).
       - If we cannot obtain a ConstantArrayType here, conservatively return (do not warn).
  5. Determine whether the current path guarantees i < ArraySize:
     - Get the symbolic value for the index:
       - ProgramStateRef State = C.getState().
       - SVal IdxVal = State->getSVal(IdxE, C.getLocationContext()).
       - If IdxVal is a concrete integer: Evaluate with EvaluateExprToInt to APSInt V; compare V.uge(ArraySize). If true, report; otherwise, return.
       - If IdxVal has a symbol: SymbolRef Sym = IdxVal.getAsSymbol().
         - const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C).
         - If Max is null:
           - The analyzer could not infer an upper bound for i on this path (which typically means no dominating check like “if (i >= TRANSFER_FUNC_POINTS) return ...” was seen). Report a warning.
         - Else:
           - Compute Bound = ArraySize - 1 (using APInt ops).
           - If Max->ugt(Bound), report a warning.
           - Else, do nothing (path is proven safe, e.g., after “if (i >= TRANSFER_FUNC_POINTS) return false;”).
  6. Reporting:
     - Create a BugType once (e.g., static std::unique_ptr<BugType> BT).
     - Generate a non-fatal error node via C.generateNonFatalErrorNode().
     - Create a PathSensitiveBugReport with a concise message, e.g.:
       - "Index i may exceed TRANSFER_FUNC_POINTS when indexing transfer-function LUT"
     - Attach the ArraySubscriptExpr as the location.
     - Emit the report.

Notes on this approach:
- Path-sensitivity: The post-fix guarded code (“if (i >= TRANSFER_FUNC_POINTS) return false;”) yields a state on the non-returning path where the constraint manager knows i < TRANSFER_FUNC_POINTS. inferSymbolMaxVal will then provide a safe upper bound and suppress the warning.
- Pre-fix code: There is no constraint tying i to the LUT size; inferSymbolMaxVal returns null or a large bound, so we warn.
- Focus: We only target the exact arrays output_tf->tf_pts.{red,green,blue} and index i, avoiding over-reporting.

B) No other callbacks required
- checkPreCall/checkPostCall, checkBind, evalAssume, checkBranchCondition, etc., are not necessary for this focused checker. The constraint manager already captures branch assumptions, and we only need their effect at use sites (checkLocation).

3) Helper logic to include in the plan (small utilities you implement)
- A helper to fetch ConstantArrayType length from the color MemberExpr chain:
  - Given ASE->getBase(), obtain the underlying MemberExpr (color field) via findSpecificTypeInChildren<MemberExpr>.
  - From its FieldDecl type, extract ConstantArrayType and size.
- Use provided utilities:
  - ExprHasName to recognize "output_tf", "tf_pts", and "{red,green,blue}" in BaseE, and "i" in IdxE.
  - EvaluateExprToInt to handle constant indices (unlikely here but safe).
  - inferSymbolMaxVal to interrogate the constraint manager about i’s maximum on the current path.

4) Reporting message
- Keep it short and clear:
  - "Index i may exceed TRANSFER_FUNC_POINTS when indexing transfer-function LUT"
