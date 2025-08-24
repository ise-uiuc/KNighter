1) Program state
- No custom program state is needed. This checker is most naturally implemented as an AST-level consistency check:
  - Detect that a function is wired as .dt_node_to_map in a struct where .dt_free_map is set to a manual-free helper (pinconf_generic_dt_free_map or pinctrl_utils_free_map).
  - Inside that function body, detect devm_* allocations used for the returned pinctrl map (either directly assigned to *map or via a temporary).

2) Callbacks and implementation details

Step A — Collect the wiring between .dt_node_to_map and .dt_free_map (checkASTDecl)
- Goal: Find structs that initialize both:
  - .dt_node_to_map = some_function
  - .dt_free_map = pinconf_generic_dt_free_map (or pinctrl_utils_free_map)
- Data kept in checker instance (no ProgramState):
  - Map< const VarDecl*, { const FunctionDecl* NodeToMapFn; bool HasManualFree; } >
  - Set< const FunctionDecl* > DangerousDtNodeToMapFns (all NodeToMap functions in structs that also set .dt_free_map to a manual-free helper)

- How to implement:
  1) In checkASTDecl(const FunctionDecl*, ...) do nothing.
  2) In checkASTDecl(const VarDecl *D, ...):
     - If D has an initializer and its type is a RecordType (struct), inspect the initializer:
       - If InitListExpr/DesignatedInitExprs are present, iterate each designated initializer.
       - For each DesignatedInitExpr, read the field designator name:
         - If it’s "dt_node_to_map": extract the referenced FunctionDecl (handle '&fn', implicit casts, etc.).
         - If it’s "dt_free_map": extract the referenced entity and check name equality against:
           - "pinconf_generic_dt_free_map"
           - "pinctrl_utils_free_map"
           Use ExprHasName(...) helper on the initializer expression to robustly match the name.
       - Store the findings in the map for this VarDecl (NodeToMapFn and HasManualFree).
     - If after processing the initializer we have both NodeToMapFn != nullptr and HasManualFree == true, insert NodeToMapFn into DangerousDtNodeToMapFns.

Notes:
- You don’t need to depend on the type being specifically struct pinctrl_ops or pinctrl_desc; just rely on field names in designated initializers.
- Handle both direct DeclRefExpr and address-of function (&func) patterns.

Step B — Within dangerous .dt_node_to_map functions, detect devm_* allocation of pinctrl_map used as the returned map (checkASTCodeBody)
- Goal: For any FunctionDecl F in DangerousDtNodeToMapFns, ensure it does not allocate the pinctrl map with devm_*.
- Detection patterns to look for in F’s body:
  1) Direct assignment:
     - BinaryOperator (BO_Assign) where LHS is dereference of the 'map' parameter, i.e., UnaryOperator '*' applied to the parameter that has the type struct pinctrl_map **.
     - RHS is a CallExpr to a known devm allocator (e.g., devm_kcalloc, devm_kmalloc, devm_kmalloc_array, devm_kzalloc).
  2) Indirect assignment via a temporary:
     - BinaryOperator (BO_Assign) where LHS is a variable Var of type struct pinctrl_map* and RHS is a CallExpr to a known devm allocator.
     - Later in the same function, a BinaryOperator (BO_Assign) where LHS is UnaryOperator '*' on the 'map' parameter (struct pinctrl_map **), and RHS uses the same Var (match by DeclRefExpr to Var or use ExprHasName to match Var’s name).

- How to implement:
  1) First, identify the 'map' parameter:
     - Iterate F->parameters().
     - Find a ParmVarDecl whose type is a pointer-to-pointer to a record named "pinctrl_map":
       - For the type T:
         - If T is PointerType, get PointeeType P1.
         - If P1 is PointerType, get PointeeType P2.
         - If P2 is RecordType whose RecordDecl has name "pinctrl_map", this is the 'map' parameter.
  2) Walk the body statements (a simple recursive AST walk or a stack-based traversal) and collect:
     - All assignments (BinaryOperator with opcode BO_Assign).
     - For each assignment:
       - Case 1 (direct):
         - If LHS is UnaryOperator '*' of DeclRefExpr to the 'map' parameter:
           - If RHS is a CallExpr whose callee name matches a known devm allocator (see list below), record a violation immediately.
       - Case 2 (indirect via temp):
         - If LHS is a DeclRefExpr bound to a local VarDecl of type struct pinctrl_map* and RHS is a CallExpr to a known devm allocator, remember this VarDecl as DevmAllocMapVar and remember the CallExpr for reporting.
     - After collecting DevmAllocMapVar, scan assignments again for "*map = DevmAllocMapVar". To match RHS:
       - Prefer matching via DeclRefExpr to the same VarDecl.
       - If casts or implicit conversions exist, use ExprHasName(RHS, VarDecl->getName()) as a fallback.
  3) If either pattern is found, create a report.

- Known devm allocators to match (callee name exact match):
  - "devm_kcalloc"
  - "devm_kmalloc"
  - "devm_kmalloc_array"
  - "devm_kzalloc"
  - "devm_kmemdup"
  - "devm_krealloc"
  (This list is conservative for map allocations; matching any of these is fine since mixing with dt_free_map is the core issue.)

- Reporting:
  - Use checkASTCodeBody’s BugReporter &BR to emit a BasicBugReport.
  - Bug type: "Double free: devm-managed map with dt_free_map".
  - Message: "devm_* allocation for pinctrl map mixed with dt_free_map causes double free".
  - Location: prefer the CallExpr of the devm_* allocation; if only indirect evidence is available, anchor at the "*map =" assignment.
  - Only report once per function body (guard with a local boolean).

Step C — Helper details and utilities
- Function/type helpers:
  - Use ExprHasName(E, "pinconf_generic_dt_free_map", C) and ExprHasName(E, "pinctrl_utils_free_map", C) when checking .dt_free_map initializers in DesignatedInitExpr.
  - To robustly get the function from a designated initializer:
    - Strip ImplicitCastExpr and UnaryOperator(UO_AddrOf).
    - Expect DeclRefExpr -> FunctionDecl.
  - To check pinctrl_map types:
    - For a QualType QT:
      - PointerType level 1: struct pinctrl_map*
      - PointerType level 2: struct pinctrl_map**
      - Use getAs<PointerType>(), then getPointeeType().getTypePtr()->getAs<RecordType>() and compare RecordDecl->getName() to "pinctrl_map".

- AST search:
  - A simple manual traversal of Stmt children is enough. Optionally, use findSpecificTypeInChildren<CallExpr> or <BinaryOperator> for convenience in tight scopes, but a small DFS over the function body is straightforward.

3) Summary of concise logic
- checkASTDecl:
  - Parse struct variable initializers with designated initializers.
  - If a variable sets both .dt_node_to_map = F and .dt_free_map is a manual-free function, add F to DangerousDtNodeToMapFns.
- checkASTCodeBody:
  - If D is a FunctionDecl F present in DangerousDtNodeToMapFns:
    - Find the parameter of type struct pinctrl_map **.
    - Detect either:
      - "*map = devm_* (...)" directly, or
      - "Var: pinctrl_map* = devm_* (...)" and later "*map = Var".
    - If found, emit a BasicBugReport at the devm_* call (or the assignment) with the short message.

4) Report text
- Use a short message: "devm_* allocation for pinctrl map mixed with dt_free_map causes double free".
