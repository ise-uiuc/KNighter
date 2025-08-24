1) Program state
- No custom program state is required. The bug is a structural/lexical pattern within a single function body.

2) Chosen callbacks
- Implement the checker in checkASTCodeBody. Perform an AST, source-order-aware structural scan of each function body to detect:
  - Per-iteration allocation of a net_device in a loop.
  - Possible early-exit statements before the first register_netdev() call for the allocated net_device.
  - Absence of free_netdev(ndev) on those early-exit paths.

3) Detailed steps in checkASTCodeBody
- High-level scanning plan:
  - For each FunctionDecl with a body, traverse its Stmt subtree.
  - Locate loops (ForStmt, WhileStmt, DoStmt). For each loop, analyze its CompoundStmt body against the target pattern.

- Helper utilities to implement:
  - isCalleeNamed(const CallExpr *CE, ArrayRef<StringRef> Names):
    - Extract the callee identifier and check against a small set of names.
  - getAssignedVarFromCall(const CallExpr *CE):
    - Identify the LHS variable receiving CE’s return:
      - Case A: DeclStmt with a single VarDecl whose init is CE.
      - Case B: BinaryOperator ‘=’ whose RHS is CE and whose LHS is a DeclRefExpr.
    - Use findSpecificTypeInParents<DeclStmt> and findSpecificTypeInParents<BinaryOperator> to detect each case.
    - Return the VarDecl* of the assigned variable (or nullptr if not found).
  - isArgumentVar(const Expr *Arg, const VarDecl *VD, CheckerContext &C):
    - Return true if Arg source text contains VD->getName() using ExprHasName.
  - isNetdevAllocCall(const CallExpr *CE):
    - Return true for alloc_etherdev, alloc_netdev, alloc_netdev_mqs (extendable).
  - isRegisterNetdevForVar(const CallExpr *CE, const VarDecl *VD, CheckerContext &C):
    - Return true if CE callee is register_netdev and CE->getNumArgs() == 1 and isArgumentVar(CE->getArg(0), VD).
  - isFreeNetdevForVar(const CallExpr *CE, const VarDecl *VD, CheckerContext &C):
    - Return true if CE callee is free_netdev and CE->getNumArgs() == 1 and isArgumentVar(CE->getArg(0), VD).
  - stmtIsBetween(SourceManager &SM, const Stmt *A, const Stmt *Mid, const Stmt *B):
    - Return true if A ends before Mid begins and Mid ends before B begins (TU order).

- Loop analysis workflow:
  1) For each loop L (ForStmt/WhileStmt/DoStmt), let Body be the loop’s CompoundStmt (or the single Stmt treated as a body).
  2) Collect all CallExpr nodes within Body (findSpecificTypeInChildren<CallExpr> will give only one; instead traverse children manually or do a small recursive walk of Body to gather all CallExpr, GotoStmt, ReturnStmt, IfStmt under L).
  3) For each CallExpr CE in Body where isNetdevAllocCall(CE) is true:
     - Determine the assigned LHS variable V via getAssignedVarFromCall(CE). If V is null, skip (we only support obvious assignment/decl patterns).
     - Identify the first register_netdev call for V after CE:
       - Among all CallExpr nodes in Body, find those where isRegisterNetdevForVar(CE2, V) is true and stmtIsBetween(SM, CE, CE2, LoopEndSentinel) holds; choose the CE2 with the smallest begin location greater than CE end location. If none is found, set RegBound = nullptr (we still check early-exits up to loop end, but the absence of register_netdev likely increases risk).
     - Compute the “at-risk segment”:
       - Start = CE (the allocation).
       - End = RegBound if found, otherwise the end of Body (we can approximate with Body end location).
  4) Within that segment, detect early exits:
     - Gather all GotoStmt and ReturnStmt that satisfy stmtIsBetween(SM, Start, ExitStmt, End).
     - Exclusion: skip exits that are guarding allocation-failure of V itself:
       - If the nearest enclosing IfStmt for ExitStmt has a condition that references V by name (ExprHasName(Cond, V->getName(), C)) and the condition is a “null test” pattern such as:
         - UnaryOperator kind UO_LNot on V, or
         - BinaryOperator (==/!=) where one side references V and the other references NULL/0,
         then ignore this ExitStmt (no need to free when V is NULL).
       - To get nearest enclosing IfStmt, use findSpecificTypeInParents<IfStmt>(ExitStmt, C).
     - For each remaining ExitStmt (Goto/Return) in that segment, check for a local free:
       - Find the immediate enclosing CompoundStmt Block that contains ExitStmt using findSpecificTypeInParents<CompoundStmt>(ExitStmt, C).
       - Inspect the statements within Block in source order from after Start up to just before ExitStmt for a call isFreeNetdevForVar(Call, V). You can do this by scanning the CompoundStmt’s children and checking their source positions relative to Start and ExitStmt.
       - If no such free_netdev(V) call exists prior to the ExitStmt in the same Block, this is a violation candidate.
  5) Optional confidence boost (heuristic, skip if it complicates the implementation):
     - If ExitStmt is a GotoStmt, retrieve its label name. If it is a common cleanup label like “exit”, and the labeled statement later in TU contains a while/for loop freeing only “older” iterations (e.g., a WhileStmt with a PreDec ‘--i’ in the condition), and contains free_netdev on something other than V (e.g., array element), then we can note higher confidence. This step can be omitted to keep the checker simple.

- Reporting:
  - For each violation candidate, create a BasicBugReport:
    - Bug type: “Leak on early exit before register_netdev”
    - Message: “net_device allocated in loop may leak on early exit; missing free_netdev(ndev) before goto/return.”
    - Anchor the report at the GotoStmt or ReturnStmt range. Optionally add a note/range at the allocation CE.
  - Use generateNonFatalErrorNode if needed to get a node for the report. Otherwise, BasicBugReport is sufficient for AST checkers.

4) Matching details and heuristics
- Allocation functions:
  - Recognize: alloc_etherdev, alloc_netdev, alloc_netdev_mqs (extendable via a small list).
- Registration function:
  - Recognize: register_netdev (single argument).
- Free function:
  - Recognize: free_netdev (single argument).
- Loop identification:
  - ForStmt, WhileStmt, DoStmt, ensuring we’re operating on a per-iteration allocation pattern.
- Early exits:
  - GotoStmt (most common for cleanup paths).
  - ReturnStmt (early returns also applicable).
- Avoid false positives on allocation failure:
  - Skip exits whose enclosing IfStmt condition tests V for NULL as described above.

5) Use of provided utilities
- findSpecificTypeInParents<T>:
  - To find enclosing DeclStmt/BinaryOperator for LHS resolution, and enclosing IfStmt/CompoundStmt for exit checks.
- findSpecificTypeInChildren<T>:
  - To collect CallExpr nodes for allocation/registration/free checks under loop bodies or blocks.
- ExprHasName:
  - To match that register_netdev or free_netdev argument refers to the same variable (e.g., “ndev”).
- EvaluateExprToInt / inferSymbolMaxVal / getArraySizeFromExpr / getStringSize / getMemRegionFromExpr / functionKnownToDeref:
  - Not required for this checker.

6) Minimal data flow
- No alias or symbolic reasoning is needed. Work only with obvious local variables (“ndev”) in the same block/loop. This keeps the checker simple and robust.

7) Success criterion (what triggers a report)
- Inside a loop, a net_device pointer variable V is assigned the result of alloc_etherdev/alloc_netdev*.
- There exists a goto/return between that allocation and the first register_netdev(V).
- The goto/return is not guarded by a “V is NULL” condition.
- There is no free_netdev(V) lexically before the goto/return within the same block.
- Emit one report per offending early-exit site.
