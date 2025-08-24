1) Program state
- No custom program states are needed. This checker is a local call-site pattern match; we avoid alias/flow tracking to keep it simple and robust.

2) Callbacks and implementation steps

A) checkPostCall
Goal: Detect calls to copy_from_sockptr-like APIs in setsockopt handlers where the size argument is a fixed sizeof(...) (or other constant) and is not validated against the function’s optlen.

Implementation details:
1. Filter relevant callees:
   - Obtain the callee identifier: if it’s not one of:
     - "copy_from_sockptr"
     - "copy_from_sockptr_offset"
     then return.
   - If the callee is "bt_copy_from_sockptr" (or other helper enforcing optlen), return since that’s the correct pattern.

2. Identify the setsockopt-like context:
   - Get the containing function: const FunctionDecl *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl()).
   - If FD is null, return.
   - Heuristically consider it a setsockopt handler if either:
     - The function name contains "setsockopt" (case-insensitive compare on FD->getNameAsString()).
     - OR the function has:
       - A parameter whose type name contains "sockptr_t" (use QT.getAsString() or Type printing), remember this parameter (SockptrParam).
       - A parameter named exactly "optlen" of integer type (remember this parameter, OptlenParam).
   - If neither heuristic matches, return. We only want to warn in setsockopt-like contexts.

3. Determine argument positions:
   - For "copy_from_sockptr": sizeArgIdx = 2, sockptrArgIdx = 1.
   - For "copy_from_sockptr_offset": sizeArgIdx = 3, sockptrArgIdx = 1.
   - Bounds check the indices against Call.getNumArgs(); if out of range, return.

4. Extract key expressions:
   - const Expr *SizeE = Call.getArgExpr(sizeArgIdx).
   - const Expr *SockptrE = Call.getArgExpr(sockptrArgIdx).

5. Ensure we are copying from the externally provided sockptr argument:
   - If SockptrParam was identified in step 2:
     - If ExprHasName(SockptrE, SockptrParam->getName()) == false, return.
       (This avoids warning on internal/local sockptr sources not tied to the API parameter.)

6. Check whether size is tied to optlen:
   - If OptlenParam was identified in step 2:
     - If ExprHasName(SizeE, OptlenParam->getName()) is true, return.
       (The size calculation mentions optlen; accept as validated. This also allows patterns like min(optlen, ...).)

7. Check for fixed-size anti-pattern:
   - Use the helper EvaluateExprToInt to see if the size is a compile-time constant:
     - llvm::APSInt Dummy; bool IsConst = EvaluateExprToInt(Dummy, SizeE, C).
   - Or syntactically detect sizeof usage:
     - bool MentionsSizeof = ExprHasName(SizeE, "sizeof").
   - If neither IsConst nor MentionsSizeof is true, return.
     - This restriction minimizes false positives (e.g., “len” computed elsewhere).

8. Emit a bug report:
   - Create a BugType once (e.g., "Missing optlen validation in setsockopt") and reuse it.
   - Generate a non-fatal error node (auto N = C.generateNonFatalErrorNode()).
   - If N is null, return.
   - Create and emit a PathSensitiveBugReport:
     - Title: "copy_from_sockptr without optlen validation"
     - Message: "Fixed-size copy_from_sockptr not checked against optlen; may read past the provided buffer"
     - Location: at the call expression.
   - This clearly points the developer to the problematic call.

Notes/heuristics applied:
- We only warn when:
  - The call is to copy_from_sockptr/copy_from_sockptr_offset.
  - The function looks like a setsockopt handler (by name or parameters).
  - The source sockptr argument is the API’s sockptr parameter (e.g., ‘optval’).
  - The size argument is a fixed constant/sizeof and does not mention optlen.
- We do not warn when:
  - bt_copy_from_sockptr() is used.
  - The size argument mentions optlen.
  - The call is not in a setsockopt-like context.

3) Optional helper utilities (internal to the checker)
- isCopyFromSockptrLike(const CallEvent &Call):
  - Returns true/false and provides the size argument index and the sockptr argument index based on the callee name.
- inSetsockoptContext(const FunctionDecl *FD, ParmVarDecl* &SockptrParam, ParmVarDecl* &OptlenParam):
  - Applies the heuristics described above (function name contains "setsockopt" OR has both sockptr_t parameter and an integer parameter named "optlen").
- Uses provided utilities:
  - ExprHasName(...) to check whether the size expression mentions "optlen" and whether the sockptr argument mentions the sockptr parameter name.
  - EvaluateExprToInt(...) to detect constant sizes.

4) No other callbacks needed
- Do not use checkBranchCondition, checkBind, or states; the checker intentionally avoids flow/alias complexity to keep it simple and precise to the target pattern.

5) Reporting message
- Keep it short and clear:
  - "copy_from_sockptr uses fixed size without validating optlen"
  - Optionally add a short guidance sentence in the same message: "Use bt_copy_from_sockptr(..., sizeof(obj), optval, optlen) or validate optlen == sizeof(obj)."
