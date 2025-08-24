```
Goal
Detect the pattern “allocate pointer A but immediately check pointer B for NULL,” e.g.:
  A = kzalloc(...);
  if (!B)
    return -ENOMEM;
The fix should be to check A rather than B.

1) Program state customization
- Keep the checker simple and precise around the immediate post-allocation NULL-check:
  - REGISTER_TRAIT_WITH_PROGRAMSTATE(LastAllocRegion, const MemRegion *)
    - The lvalue region receiving the result of the last allocation call.
  - REGISTER_TRAIT_WITH_PROGRAMSTATE(LastAllocBlock, const Stmt *)
    - The nearest parent CompoundStmt (lexical block) containing the allocation. Used to ensure proximity.
  - REGISTER_TRAIT_WITH_PROGRAMSTATE(LastAllocExpr, const Expr *)
    - The LHS expression used at the allocation assignment (for printing a useful name in the report).

No alias map is used to keep the checker simple. (It can be extended later if needed.)

2) Helper utilities (internal to the checker)
- bool isAllocCall(const CallEvent &Call)
  - Returns true for common kernel allocators whose return can be NULL:
    - "kzalloc", "kmalloc", "kcalloc", "kvzalloc", "kvmalloc", "kzalloc_node",
      "kmalloc_node", "krealloc", "kmemdup", "devm_kzalloc", "devm_kmalloc"
    - Extendable by name if needed.
- const MemRegion *getAssignedRegionOfCall(const CallEvent &Call, CheckerContext &C)
  - For Call.getOriginExpr() (CallExpr CE):
    - Try parent BinaryOperator (findSpecificTypeInParents<BinaryOperator>(CE, C)):
      - If BO_Assign, return getMemRegionFromExpr(BO->getLHS(), C).
    - Else try parent DeclStmt (findSpecificTypeInParents<DeclStmt>(CE, C)):
      - For a single VarDecl with an initializer containing CE, return the MemRegion of that variable (getMemRegionFromExpr on its DeclRefExpr).
    - Else return nullptr (no direct assignment; ignore).
- const CompoundStmt *getEnclosingBlock(const Stmt *S, CheckerContext &C)
  - Use findSpecificTypeInParents<CompoundStmt>(S, C).
- bool isNullLiteralExpr(const Expr *E, CheckerContext &C)
  - After IgnoreParenImpCasts:
    - Return true if E is: GNUNullExpr, CXXNullPtrLiteralExpr, or IntegerLiteral(0) or contains "NULL" via ExprHasName(E, "NULL", C).
- bool isNegativeNullCheck(const Stmt *Cond, const Expr *&PtrExpr, CheckerContext &C)
  - Extract the pointer expression being checked for NULL:
    - If UnaryOperator with UO_LNot: PtrExpr = subexpr; return true.
    - If BinaryOperator with BO_EQ and one side is null-literal: PtrExpr = other side; return true.
    - If plain pointer (if (ptr)) or BO_NE: return false (not a failure-path NULL check).
- bool thenBranchReturnsENOMEM(const IfStmt *IS, CheckerContext &C)
  - From IS->getThen(), findSpecificTypeInChildren<ReturnStmt>.
  - If found and return expression contains "ENOMEM" (ExprHasName(retExpr, "ENOMEM", C)), return true; else false.
- StringRef getExprText(const Expr *E, CheckerContext &C)
  - Use SourceManager+Lexer similarly to ExprHasName to extract source text for messages.

3) Callback selection and detailed behavior
- checkBeginFunction(CheckerContext &C)
  - Clear LastAllocRegion/LastAllocBlock/LastAllocExpr at function entry.

- checkPostCall(const CallEvent &Call, CheckerContext &C)
  - If !isAllocCall(Call), return.
  - Find the assigned region: R = getAssignedRegionOfCall(Call, C).
    - If R is nullptr, ignore (allocation result not stored to an lvalue).
  - Compute the enclosing block of CE: B = getEnclosingBlock(Call.getOriginExpr(), C).
  - Record in state:
    - LastAllocRegion = R
    - LastAllocBlock = B
    - LastAllocExpr = the LHS Expr of the assignment (BO->getLHS() or the VarDecl’s DeclRefExpr).
  - Overwrite any previous recorded allocation (we only care about the most recent allocation).

- checkBranchCondition(const Stmt *Condition, CheckerContext &C)
  - Retrieve LastAllocRegion (AR), LastAllocBlock (AB), LastAllocExpr (AE). If any is null, return.
  - Find the IfStmt owning this condition:
    - const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C). If null, return.
  - Ensure proximity: Let CB = getEnclosingBlock(IS, C). If CB != AB:
    - Not in the same lexical block anymore; clear LastAllocRegion/LastAllocBlock/LastAllocExpr and return, to avoid stale state.
  - Extract the pointer expr checked for NULL:
    - const Expr *CheckedPtr = nullptr;
    - If !isNegativeNullCheck(Condition, CheckedPtr, C), return (we only match the failure-path NULL check).
  - Additional filter for precision:
    - If !thenBranchReturnsENOMEM(IS, C), return (we focus on the pattern “if (!ptr) return -ENOMEM;”).
  - Compute the region of the checked pointer: const MemRegion *CR = getMemRegionFromExpr(CheckedPtr, C).
    - If CR == nullptr, return.
    - If CR == AR:
      - This is a correct NULL check for the recent allocation. Clear LastAllocRegion/LastAllocBlock/LastAllocExpr and return.
    - Else:
      - This matches the target bug pattern:
        - An allocation stored into AR was followed by a failure-path NULL check on a different pointer CR.
      - Report:
        - Generate a non-fatal error node.
        - Build a short message, preferably including both expressions’ texts:
          - Allocated pointer not NULL-checked; different pointer checked after allocation
          - or "Allocated '<AE text>' but checked '<CheckedPtr text>' for NULL"
        - Create PathSensitiveBugReport and emit.
      - Clear LastAllocRegion/LastAllocBlock/LastAllocExpr to avoid duplicate reports.

- Optional cleanup:
  - On any subsequent allocation (handled in checkPostCall), the recorded state will be overwritten.
  - No need for checkEndFunction.

4) Notes on false positives and scope control
- Proximity is controlled by requiring:
  - The check happens in the same CompoundStmt as the allocation.
  - The check is a negative NULL check and the then-branch returns ENOMEM.
- This mirrors the kernel pattern “if (!ptr) return -ENOMEM;” immediately after allocation, significantly reducing noise.
- The checker purposefully does not implement alias tracking to stay simple; it targets the straightforward and most harmful pattern as in the provided patch.

5) Bug report
- Use a single BugType, e.g., “Mismatched NULL check after allocation”.
- Message (short and clear):
  - “Allocated one pointer but checked a different pointer for NULL”
  - If including names: “Allocated ‘<alloc-lhs>’ but checked ‘<checked-expr>’ for NULL”
- Use generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>(...).

```
