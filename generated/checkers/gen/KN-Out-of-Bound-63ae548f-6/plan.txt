Plan

1. Program state
- No custom program state maps or traits are required. This checker can be implemented with localized (per-visit) reasoning aided by constant evaluation and simple ancestor-condition inspection.

2. Callback functions
- checkPostStmt<ArraySubscriptExpr>
  - Goal: Detect array indexing into output_tf->tf_pts.{red, green, blue}[idx] where idx is not proven to be within the array’s bound (TRANSFER_FUNC_POINTS).
  - Steps:
    1) Filter to the target arrays:
       - Get the base expression of the ArraySubscriptExpr (ASE->getBase()->IgnoreParenImpCasts()).
       - Ensure it is a MemberExpr (ME) chain that matches the shape “(...)->tf_pts.red” or “(...).tf_pts.red” (and analogously for green, blue).
         - Walk the MemberExpr chain upward:
           - The final member name must be one of: "red", "green", "blue".
           - The immediate parent member name in the chain must be "tf_pts".
         - If this does not hold, ignore the access.
    2) Retrieve the array bound (TRANSFER_FUNC_POINTS) from the type:
       - From the MemberExpr’s member declaration (FieldDecl) corresponding to "red"/"green"/"blue", obtain FieldDecl->getType().
       - If the type is a ConstantArrayType, read its size via getSize() into an APInt ArrSize.
       - If it is not a ConstantArrayType (e.g., decayed to pointer or unknown), stop (do not warn).
    3) Analyze the index expression:
       - Let IdxE = ASE->getIdx()->IgnoreParenImpCasts().
       - Try to evaluate IdxE to a constant integer:
         - Use EvaluateExprToInt. If success and IdxVal >= ArrSize, report a bug.
       - Otherwise, try a symbolic upper bound:
         - Obtain SVal for IdxE via C.getState()->getSVal(IdxE, C.getLocationContext()) and extract SymbolRef if available.
         - Call inferSymbolMaxVal(Sym, C). If it returns a max value and maxVal >= ArrSize, report a bug.
       - If neither constant nor bounded symbol info is available, conservatively check for a guarding condition nearby:
         - Attempt to locate an enclosing loop/condition that bounds the index:
           - Search ancestors using findSpecificTypeInParents for the nearest ForStmt, WhileStmt, DoStmt, or IfStmt (examine each in nearest-to-farthest order).
           - For each found condition expression CondE:
             - Determine if CondE references the same index variable(s) as in IdxE:
               - Collect DeclRefExprs inside IdxE; record their VarDecls (e.g., variable “i”).
               - Check if CondE contains any of these variables (by comparing VarDecl identity).
             - If yes, try to confirm a bound against the array size:
               - Prefer structural comparison: if CondE is/contains a BinaryOperator with opcode < or <= comparing the index variable vs a constant expression that EvaluateExprToInt returns ArrSize, or ArrSize - 1 (for <=).
               - Otherwise, textual fallback:
                 - If ExprHasName(CondE, "TRANSFER_FUNC_POINTS", C) is true and CondE also references the index variable, consider it guarded; do not warn.
           - If any such guarding comparison is found, do not warn.
         - If no guard is found, and we couldn’t prove a safe upper bound, emit a warning (heuristic).
    4) Bug reporting:
       - If a violation is found, create a non-fatal error node with generateNonFatalErrorNode().
       - Emit a PathSensitiveBugReport with a short message, e.g.:
         - "Index may exceed LUT bound when accessing tf_pts.[red|green|blue]."
       - Optionally include a note with the computed/known bound (ArrSize) when available.

3. Implementation details and guidance
- Member array bound extraction:
  - For the base expression MemberExpr ME of "red"/"green"/"blue":
    - auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    - QualType FT = FD->getType();
    - const auto *CAT = dyn_cast<ConstantArrayType>(FT.getTypePtr());
    - If CAT is null, bail out (do not warn).
    - Else, ArrSize = CAT->getSize().
- Determine the specific array name for the report:
  - From the terminal MemberExpr, retrieve its member name string ("red", "green", "blue") for the message.
- Index variable extraction:
  - Traverse IdxE to collect DeclRefExpr that refer to VarDecls; you primarily care when there is a simple variable index like “i” or derived arithmetic of “i”.
- Guard condition matching:
  - For nearest ForStmt, inspect its condition ForStmt->getCond().
  - For WhileStmt/DoStmt, inspect their condition expressions.
  - For IfStmt, inspect its condition.
  - In the condition, first try to structurally match BinaryOperator with opcodes: BO_LT, BO_LE, and check:
    - If LHS/RHS is the index variable DeclRefExpr,
    - And the comparator side EvaluateExprToInt equals ArrSize (or ArrSize - 1 for <=),
    - Then treat as guarded.
  - As a fallback, if ExprHasName(cond, "TRANSFER_FUNC_POINTS", C) and the condition references the same variable(s), treat as guarded.
- False positive control:
  - Only report when:
    - The index is a provable constant >= ArrSize, or
    - Symbolic max is known and >= ArrSize, or
    - We cannot infer a bound and we cannot find any guard; in this last case, report at most once per array expression site to reduce noise.
- Scope of checker:
  - This checker is tailored to the AMD DC “tf_pts” LUT pattern and is limited to the member arrays named red/green/blue under tf_pts to avoid broader noise, matching the target bug pattern precisely.
- No other callbacks are necessary:
  - Do not use checkBranchCondition or checkBind unless you want to enhance guard tracking. The parent-condition search is enough and keeps the checker simple.
