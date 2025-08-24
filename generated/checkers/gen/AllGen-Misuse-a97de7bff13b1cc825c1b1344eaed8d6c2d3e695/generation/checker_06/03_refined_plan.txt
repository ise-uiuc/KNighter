Plan to detect unsafe copy_from_sockptr usage without validating optlen

1) Program state
- No custom program state is required. This checker is purely syntactic/semantic at the call site.

2) Callbacks and detailed implementation

A) checkPreCall — detect the unsafe pattern at the call site
- Goal: Flag calls that read a fixed-size object from setsockopt’s optval using copy_from_sockptr/copy_from_sockptr_offset without using/validating the function’s optlen parameter.
- Steps:
  1. Identify target APIs:
     - If callee name is "copy_from_sockptr" or "copy_from_sockptr_offset", continue. Otherwise return.
     - Explicitly do nothing for "bt_copy_from_sockptr" (this is the safe API).
  2. Collect the current function’s optval/optlen parameters:
     - Get the enclosing function: const FunctionDecl *FD = C.getLocationContext()->getDecl()->getAsFunction();
     - Iterate FD->parameters():
       - Find a parameter named "optval" (ParmVarDecl*) — this is the sockptr_t argument. If absent, return (we only target setsockopt-like handlers).
       - Find a parameter named "optlen" (ParmVarDecl*). If missing, optionally fallback to a parameter named exactly "len" of an integer type. If still missing, return.
  3. Read call arguments and determine the length index:
     - For copy_from_sockptr: length index = 2 (third arg). The source sockptr index = 1 (second arg).
     - For copy_from_sockptr_offset: length index = 3 (fourth arg). The source sockptr index = 1 (second arg).
  4. Verify the source uses the optval parameter:
     - Let srcArg = Call.getArgExpr(SrcIndex).
     - If not ExprHasName(srcArg, OptvalParam->getNameAsString(), C), return (we only warn when reading from the function’s optval).
  5. Check whether the length argument ties to optlen:
     - Let lenArg = Call.getArgExpr(LenIndex).
     - Define a small helper in the checker:
       - bool usesLenParam(const Expr *E, const ParmVarDecl *LenParam, CheckerContext &C):
         - If ExprHasName(E, LenParam->getNameAsString(), C) return true.
         - Else if E is a DeclRefExpr to a local VarDecl V:
           - If V->hasInit() and V->getInit() is not null, and ExprHasName(V->getInit(), LenParam->getNameAsString(), C) return true.
         - Return false otherwise.
     - If usesLenParam(lenArg, LenParam, C) is true, consider it safe and return.
  6. Ensure it’s a fixed-size copy (to avoid false positives):
     - Try to evaluate lenArg as an integer constant using EvaluateExprToInt.
     - If EvaluateExprToInt succeeds (e.g., sizeof(u32), sizeof(obj), literal), then it’s fixed-size.
     - If it fails, return (we only flag when length is clearly a fixed size and does not use/derive from optlen).
  7. Report the bug:
     - Create a NonFatalErrorNode and emit a PathSensitiveBugReport with a short message:
       - "copy_from_sockptr reads fixed size from optval without validating optlen"
     - Highlight lenArg (the length expression) in the report.

B) Helper logic (local to the checker)
- Function to find the optval/optlen parameters in the current function:
  - Iterate FD->parameters():
    - Record OptvalParam if param->getNameAsString() == "optval".
    - Record LenParam if param->getNameAsString() == "optlen".
  - If OptvalParam is null, do not warn (not a setsockopt-like function).
  - If LenParam is null, optionally try a best-effort fallback:
    - If any integer parameter is named exactly "len", set LenParam to it.
- usesLenParam helper as defined above, using ExprHasName and VarDecl initializer check.

C) Other callbacks
- Not necessary. Do not use checkBind, checkPostStmt, or checkBranchCondition. The analysis is localized to the callsite and enclosing function signature for simplicity and low false positives.

3) Notes to reduce false positives
- Only warn when:
  - The source argument syntactically references the function’s optval parameter.
  - The length argument is a compile-time constant (e.g., sizeof(T), literal), and
  - The length argument does not directly reference optlen, nor a local variable whose initializer references optlen.
- Do not warn for bt_copy_from_sockptr (safe pattern).
- This precisely matches the buggy pattern from the patch (e.g., copy_from_sockptr(&opt, optval, sizeof(u32)) inside a function that has (optval, optlen)).

4) Utility functions used
- ExprHasName to detect references to parameter names in expressions and initializers.
- EvaluateExprToInt to confirm the length is a fixed-size constant.
