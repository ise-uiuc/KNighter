Plan to detect 32-bit left-shift widened to 64-bit after the shift (possible overflow/truncation)

1) Program state
- No custom program state is needed.

2) Core idea to detect the bug
- Find a left-shift expression (Eshl: LHS << RHS) whose result type is 32-bit (or narrower), but whose overall destination is 64-bit (for example, assigned to a u64 variable, passed to a 64-bit parameter, or returned from a 64-bit function).
- If the shift is performed in 32-bit width and only widened afterwards (via implicit cast or assignment), warn.
- Suppress the warning if the shift is already performed in 64-bit (e.g., LHS is explicitly cast to 64-bit or is a 64-bit literal like 1ULL) or if RHS is a compile-time constant strictly less than the LHS width (i.e., definitely no 32-bit overflow risk). If RHS is unknown or could be >= LHS width, warn.

3) Helper utilities
- Use findSpecificTypeInChildren<T> to:
  - Find the BinaryOperator for the shift (opcode BO_Shl) inside an expression.
  - Find any explicit cast (ExplicitCastExpr) within the left operand subtree to detect if LHS is already widened to 64-bit.
- Use EvaluateExprToInt to evaluate the RHS (shift count) when it is a constant.
- Optionally use ExprHasName if you want to further refine false positives (not strictly necessary here).

4) Shared helper: analyzeAndReportShiftToWide
- Input: Expr* E (the expression being converted/assigned), QualType DestTy (the destination integer type), CheckerContext &C, and a short context string (“initialization/assignment/return/argument”).
- Steps:
  1) Ensure DestTy is an integer type and its bit width DestW >= 64 using C.getASTContext().getIntWidth(DestTy).
  2) Find a BinaryOperator Shl inside E with opcode BO_Shl using findSpecificTypeInChildren<BinaryOperator>(E). If none, return.
  3) Let L = Shl->getLHS(), R = Shl->getRHS(). Compute widths:
     - LHSW = C.getASTContext().getIntWidth(L->getType()) (after implicit promotions).
     - ShlW = C.getASTContext().getIntWidth(Shl->getType()).
     If ShlW >= 64, return (shift already performed in 64-bit).
  4) Check if LHS already explicitly widened to 64-bit:
     - If findSpecificTypeInChildren<ExplicitCastExpr>(L) exists and its target type width >= 64, return.
     - Also, if L->getType() width >= 64, return (already wide).
  5) Analyze RHS (shift count):
     - Try EvaluateExprToInt on R. If success and value < LHSW, suppress the warning to reduce false positives.
     - Otherwise (unknown or value >= LHSW), proceed to warn.
  6) Report:
     - Create a non-fatal error node and emit a PathSensitiveBugReport with a short message like:
       “Shift done in 32-bit, widened after; cast left operand to 64-bit before <<.”
     - Highlight the source range of the shift expression (Shl->getSourceRange()).

5) Callback selection and implementation details

- checkPostStmt(const DeclStmt *DS, CheckerContext &C)
  - For each VarDecl VD in DS:
    - If VD has an initializer:
      - Let DestTy = VD->getType().
      - Let Init = VD->getInit().
      - Call analyzeAndReportShiftToWide(Init, DestTy, C, "initialization").
  - This catches cases like u64 tau4 = ((1 << x_w) | x) << y;

- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
  - Only handle assignments: if S is a BinaryOperator and isAssignmentOp():
    - BO = cast<BinaryOperator>(S).
    - DestTy = BO->getLHS()->getType().
    - RhsExpr = BO->getRHS()->IgnoreParenImpCasts().
    - Call analyzeAndReportShiftToWide(RhsExpr, DestTy, C, "assignment").
  - This catches tau4 = ((1 << x_w) | x) << y;

- checkPreStmt(const ReturnStmt *RS, CheckerContext &C)
  - If RS->getRetValue() exists:
    - Get the current FunctionDecl via C.getStackFrame()->getDecl().
    - DestTy = FD->getReturnType().
    - RetE = RS->getRetValue().
    - Call analyzeAndReportShiftToWide(RetE, DestTy, C, "return").
  - This catches return ((1 << x_w) | x) << y; in u64-returning functions.

- checkPreCall(const CallEvent &Call, CheckerContext &C)
  - For i in [0, Call.getNumArgs()):
    - const Expr *ArgE = Call.getArgExpr(i).
    - If Call.getDecl() and i < getNumParams(), get ParameterDecl P = getParamDecl(i) and DestTy = P->getType().
      - If DestTy is integer and width >= 64:
        - Call analyzeAndReportShiftToWide(ArgE, DestTy, C, "argument").
  - This catches passing a 32-bit shift to a 64-bit parameter.

6) Heuristics to reduce false positives
- Do not warn if:
  - The shift expression’s resulting type width is already >= 64 (e.g., (u64)lhs << y, 1ULL << y).
  - The RHS is a compile-time constant strictly less than the LHS width (value < LHSW).
- Warn if:
  - RHS is unknown (cannot evaluate) or can be >= LHSW.
  - Destination width >= 64 and shift is computed in < 64-bit.

7) Bug report
- Use a single BugType member (e.g., "Narrow shift widened to 64-bit") initialized once.
- Short message:
  - “Shift done in 32-bit, widened after; cast left operand to 64-bit before <<.”
- Point to the shift expression range.

This minimal, AST-driven approach robustly flags the exact pattern fixed by the patch:
- Before: u64 tau4 = ((1 << x_w) | x) << y;        // shift in 32-bit, then widen
- After:  u64 tau4 = (u64)((1 << x_w) | x) << y;   // cast to 64-bit before shift
